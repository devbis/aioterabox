import asyncio
import hashlib
import io
import json
import os
from io import IOBase
from tempfile import TemporaryDirectory
from typing import NamedTuple
from urllib.parse import quote_plus

import aiohttp

from aioterabox.exceptions import (
    TeraboxApiError,
    TeraboxChecksumMismatchError,
    TeraboxContentTypeError,
    TeraboxNotFoundError,
    TeraboxUnauthorizedError,
)

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0"
BASE_TERABOX_URL = "https://www.terabox.com"
MAX_UNCHUNKED_FILE_SIZE = 2147483648  # 2 GB
CHUNK_SIZE = 120 * 1024 * 1024
READ_BUF = 4 * 1024 * 1024  # 4 MB


class FileInfo(NamedTuple):
    name: str
    path: str
    size: int
    is_dir: bool = False


class NonClosableIO(io.IOBase):
    def __init__(self, wrapped: io.IOBase):
        self._wrapped = wrapped

    def read(self, size=-1):
        return self._wrapped.read(size)

    def readable(self):
        return True

    def seekable(self):
        return self._wrapped.seekable()

    def seek(self, offset, whence=0):
        return self._wrapped.seek(offset, whence)

    def tell(self):
        return self._wrapped.tell()

    def fileno(self):
        return self._wrapped.fileno()

    @property
    def closed(self):
        return self._wrapped.closed

    def close(self):
        pass

    def force_close(self):
        self._wrapped.close()

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


class TeraBoxClient:
    def __init__(self, jstoken: str, csrf_token: str, browserid: str, ndus: str, ndut_fmt: str,
                 lang: str = 'en') -> None:
        self.jstoken = jstoken
        self.csrf_token = csrf_token
        self.browserid = browserid
        self.ndus = ndus
        self.ndut_fmt = ndut_fmt
        self.lang = lang

        self.is_vip: bool | None = None

    @property
    def request_cookies(self) -> dict[str, str]:
        """Get the cookies needed for requests."""
        return {
            'csrfToken': self.csrf_token,
            'browserid': self.browserid,
            'lang': self.lang,
            'ndus': self.ndus,
            'ndut_fmt': self.ndut_fmt,
        }

    @staticmethod
    def file_md5(file: IOBase, chunk_size=1024 * 1024) -> str:
        h = hashlib.md5()
        for chunk in iter(lambda: file.read(chunk_size), b""):
            h.update(chunk)
        return h.hexdigest()

    def get_session(self, headers: dict[str, str]) -> aiohttp.ClientSession:
        """Get an aiohttp session with the necessary cookies and headers."""
        return aiohttp.ClientSession(
            headers={
                "User-Agent": USER_AGENT,
                "Origin": BASE_TERABOX_URL,
                "Referer": BASE_TERABOX_URL + "/main",
                **headers,
            },
            cookies=self.request_cookies,
        )

    async def check_vip_status(self) -> bool:
        """Check if the user has VIP status."""

        if self.is_vip is not None:
            return self.is_vip

        async with self.get_session(headers={
            'Referer': BASE_TERABOX_URL + "/main?category=all",
        }) as session:
            async with session.get(
                f"{BASE_TERABOX_URL}/rest/2.0/membership/proxy/user?method=query",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=19,
            ) as response:
                data = await response.json()
                vip = data["data"]["member_info"]["is_vip"]
                self.is_vip = vip == 1
                return self.is_vip

    async def get_max_file_size(self) -> int:
        """Get the maximum file size allowed for upload."""

        return 4294967296 if await self.check_vip_status() else 21474836479

    async def list_remote_directory(self, remote_dir: str) -> list[FileInfo]:
        """List the contents of a remote directory."""
        async with self.get_session(headers={"Referer": BASE_TERABOX_URL + "/main"}) as session:
            async with session.get(
                f"{BASE_TERABOX_URL}/api/list",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                params={
                    "app_id": "250528",
                    "web": "1",
                    "channel": "dubox",
                    "clienttype": "5",  # This changed from 0 to 5 in 2025
                    "jsToken": self.jstoken,
                    "dir": f"/{remote_dir.lstrip('/')}",  # Leading slash is now required
                    "num": "1000",
                    "page": "1",
                    "order": "time",
                    "desc": "1",
                    "showempty": "0"
                },
                timeout=10,
            ) as response:
                data = await response.json()
                if "errno" in data and data["errno"] != 0:
                    if data["errno"] == -7:
                        raise TeraboxNotFoundError('Remote directory not found.')
                    if data["errno"] == -6:
                        raise TeraboxUnauthorizedError('Invalid cookies.')
                    else:
                        raise TeraboxApiError(f"API error: {data}")
                response = data.get("list", [])
                return [
                    FileInfo(
                        name=entry["server_filename"],
                        path=entry["path"],
                        size=entry["size"],
                        is_dir=entry["isdir"],
                    )
                    for entry in response
                ]

    async def _upload_file_chunk(self, upload_host: str, file: IOBase, remote_path: str, chunk_md5: str, uploadid: str,
                                 partseq: int = 0, max_attempts: int = 6) -> dict:
        """Upload a file chunk to TeraBox."""
        async with self.get_session(headers={
            "Referer": BASE_TERABOX_URL + "/main?category=all",
        }) as session:
            for i in range(max_attempts - 1, -1, -1):
                file.seek(0)
                try:
                    data = aiohttp.FormData()
                    data.add_field(
                        'file',
                        NonClosableIO(file),
                        filename=os.path.basename(remote_path),
                        content_type="application/octet-stream",
                    )
                    async with session.post(
                        f"https://{upload_host}/rest/2.0/pcs/superfile2?"
                        f"method=upload&type=tmpfile&app_id=250528&path={quote_plus(remote_path)}&"
                        f"uploadid={uploadid}&partseq={partseq}",
                        data=data,
                        timeout=15,
                    ) as response:
                        content = await response.read()
                        try:
                            resp = json.loads(content)
                        except json.JSONDecodeError:
                            raise TeraboxApiError(f"File upload failed: {content.decode(errors='ignore')}")

                        if 'error_code' in resp:
                            if resp['error_code'] == 31208:
                                raise TeraboxContentTypeError(resp['error_msg'])
                            raise TeraboxApiError(f"File upload failed: {resp}")

                        if resp['md5'] != chunk_md5:
                            raise TeraboxChecksumMismatchError("MD5 hash mismatch after file upload.")
                        break
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    print('... problem, retrying upload ...')
                    if i > 0:
                        continue
                    raise
            return resp

    async def _precreate_file(self, remote_path: str, md5_list_json: list[str]) -> str:
        async with self.get_session(headers={
            "Referer": BASE_TERABOX_URL + "/main?category=all",
        }) as session:
            data = {
                "app_id": "250528",
                "web": "1",
                "channel": "dubox",
                "clienttype": "0",
                "jsToken": self.jstoken,
                "path": remote_path,
                "autoinit": "1",
                "target_path": os.path.dirname(remote_path),
                "block_list": json.dumps(md5_list_json),
            }

            async with session.post(
                f"{BASE_TERABOX_URL}/api/precreate",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=data,
                timeout=10,
            ) as response:
                resp_data = await response.json()
                if "uploadid" in resp_data:
                    return resp_data["uploadid"]
                if resp_data.get("errmsg") == 'need verify':
                    raise TeraboxUnauthorizedError(
                        "The login session has expired. Please login again and refresh the credentials."
                    )
                raise TeraboxApiError(f"File precreate failed: {resp_data}")

    async def _postcreate_file(self, remote_path: str, uploadid: str, file_size: int, md5_list_json: list[str]) -> dict:
        async with self.get_session(headers={
            "Referer": BASE_TERABOX_URL + "/main?category=all",
        }) as session:
            data = {
                "isdir": "0",
                "rtype": "1",
                "app_id": "250528",
                "jsToken": self.jstoken,
                "path": remote_path,
                "uploadid": uploadid,
                "target_path": os.path.dirname(remote_path) + '/',
                "size": str(file_size),
                "block_list": json.dumps(md5_list_json),
            }

            async with session.post(
                f"{BASE_TERABOX_URL}/api/create",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=data,
                timeout=10,
            ) as response:
                resp_data = await response.json()
                if resp_data.get("errno") == 0:
                    return resp_data
                raise TeraboxApiError(f"File create failed: {resp_data}")

    async def _locate_upload_host(self) -> str:
        """Locate the upload server."""
        async with self.get_session(headers={
            "Referer": BASE_TERABOX_URL + "/main?category=all",
        }) as session:
            async with session.get(
                "https://d.terabox.com/rest/2.0/pcs/file?method=locateupload",
            ) as response:
                resp_data = await response.json(content_type=None)
                host = resp_data.get("host")
                if not host:
                    raise TeraboxApiError(f"Locate upload server failed: {resp_data}")
                return host

    async def upload_file(self, file: IOBase, destination_path: str) -> dict:
        """Upload a file to TeraBox.

        @param filepath: path to the file to upload
        @param filename: name of the file to upload
        @param parent_id: id of the parent folder
        """

        file_size = file.seek(0, 2)
        file.seek(0)
        max_file_size = await self.get_max_file_size()
        if file_size > max_file_size:
            raise ValueError(f"File size {file_size} exceeds maximum allowed size of {max_file_size} bytes.")

        with TemporaryDirectory() as tmpdir:
            chunks = []
            file_chunks_md5 = []
            if file_size > MAX_UNCHUNKED_FILE_SIZE:
                num_chunks = file_size // CHUNK_SIZE
                base_filename = os.path.basename(destination_path)
                for i in range(num_chunks):
                    chunk_filename = os.path.join(tmpdir, f"{base_filename}.part{i:03d}")
                    written = 0
                    md5 = hashlib.md5()

                    file.seek(i * CHUNK_SIZE)
                    with open(chunk_filename, 'wb') as chunk_file:
                        while written < CHUNK_SIZE:
                            to_read = min(READ_BUF, CHUNK_SIZE - written)
                            data = None
                            if to_read:
                                data = file.read(to_read)
                            if not data:
                                break

                            chunk_file.write(data)
                            md5.update(data)
                            written += len(data)
                    file_chunks_md5.append(md5.hexdigest())
                    chunks.append(chunk_filename)

            else:
                file_chunks_md5 = [self.file_md5(file)]
                file.seek(0)
                chunks = [file]

            upload_host = await self._locate_upload_host()
            uploadid = await self._precreate_file(destination_path, file_chunks_md5)
            chunk_results = []
            for partseq, (chunk, chunk_md5) in enumerate(zip(chunks, file_chunks_md5, strict=True)):
                is_filename = False
                if isinstance(chunk, str):
                    chunk = open(chunk, 'rb')
                    is_filename = True
                try:
                    resp = await self._upload_file_chunk(
                        upload_host=upload_host,
                        file=chunk,
                        remote_path=destination_path,
                        chunk_md5=chunk_md5,
                        uploadid=uploadid,
                        partseq=partseq,
                    )
                finally:
                    if is_filename:
                        chunk.close()
                chunk_results.append(resp)

            final_resp = await self._postcreate_file(
                remote_path=destination_path,
                uploadid=uploadid,
                file_size=file_size,
                md5_list_json=file_chunks_md5,
            )

        return final_resp

    async def _filemanager(self, operation: str, remote_paths: list[str | dict]) -> dict:
        """
        For Delete: ["/path1","path2.rar"]
        For Move: [{"path":"/myfolder/source.bin","dest":"/target/","newname":"newfilename.bin"}]
        For Copy same as move
        + "ondup": newcopy, overwrite (optional, skip by default)
        For rename [{"id":1111,"path":"/dir1/src.bin","newname":"myfile2.bin"}]

        operation - copy (file copy), move (file movement), rename (file renaming), and delete (file deletion)
        opera=copy: filelist: [{"path":"/hello/test.mp4","dest":"","newname":"test.mp4"}]
        opera=move: filelist: [{"path":"/test.mp4","dest":"/test_dir","newname":"test.mp4"}]
        opera=rename: filelist：[{"path":"/hello/test.mp4","newname":"test_one.mp4"}]
        opera=delete: filelist: ["/test.mp4"]

        """

        async with self.get_session(headers={
            "Referer": BASE_TERABOX_URL + "/main?category=all",
        }) as session:
            data = {
                "app_id": "250528",
                "web": "1",
                "channel": "dubox",
                "clienttype": "0",
                "jsToken": self.jstoken,
                "filelist": json.dumps(remote_paths),
            }

            async with session.post(
                f"{BASE_TERABOX_URL}/api/filemanager?opera={operation}&jsToken={self.jstoken}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=data,
                timeout=10,
            ) as response:
                resp_data = await response.json()
                if resp_data.get("errno") == 0:
                    return resp_data
                raise TeraboxApiError(f"File delete failed: {resp_data}")

    async def delete_files(self, remote_paths: list[str]) -> dict:
        """Delete a file from TeraBox.

        @param remote_path: path to the file to delete
        """

        return await self._filemanager('delete', remote_paths)

    async def copy_file(self, remote_src_path: str, remote_dst_path: str) -> dict:
        """Copy a file in TeraBox.

        @param remote_src_path: path to the source file
        @param remote_dst_path: path to the destination file
        """

        return await self._filemanager('copy', [{
            "path": remote_src_path,
            "dest": os.path.dirname(remote_dst_path),
            "newname": os.path.basename(remote_dst_path),
        }])

    async def move_file(self, remote_src_path: str, remote_dst_path: str) -> dict:
        """Copy a file in TeraBox.

        @param remote_src_path: path to the source file
        @param remote_dst_path: path to the destination file
        """

        return await self._filemanager('copy', [{
            "path": remote_src_path,
            "dest": os.path.dirname(remote_dst_path),
            "newname": os.path.basename(remote_dst_path),
        }])

    async def rename_file(self, remote_src_path: str, new_name: str) -> dict:
        """Rename a file in TeraBox.

        @param remote_src_path: path to the source file
        @param new_name: new name for the file
        """

        return await self._filemanager('rename', [{
            "path": remote_src_path,
            "newname": new_name,
        }])

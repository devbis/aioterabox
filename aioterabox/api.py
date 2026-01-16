import hashlib
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Any, NamedTuple, TypedDict, get_type_hints
from urllib.parse import quote_plus

import aiofiles
import aiofiles.os
import aiohttp
from aiofiles.threadpool.binary import AsyncBufferedReader

from .aiofile_payload import AioFilePayload
from .encryption import change_base64_type, decrypt_aes, encrypt_rsa, sign_download
from .exceptions import (
    TeraboxApiError,
    TeraboxChecksumMismatchError,
    TeraboxContentTypeError,
    TeraboxNotFoundError,
    TeraboxUnauthorizedError,
)

LOGGER = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0"
BASE_TERABOX_URL = "https://www.terabox.com"
INITIAL_URL = "https://www.terabox.app/wap/share/filelist?surl=12345678"
MAX_UNCHUNKED_FILE_SIZE = 10 * 1024 * 1024  # 10 mb
CHUNK_SIZE = 4 * 1024 * 1024
READ_BUF = 1 * 1024 * 1024  # 1 MB


class TeraboxCookies(TypedDict):
    jstoken: str  # not a cookie but we store it here for convenience
    csrfToken: str
    browserid: str
    ndus: str


class DownloadResponse(TypedDict):
    fs_id: str
    dlink: str


class FileInfo(NamedTuple):
    name: str
    path: str
    size: int
    is_dir: bool = False


class AccountInfo(TypedDict):
    account_id: str | None
    display_name: str
    head_url: str


def prand_gen(client: str, seval: str, encpwd: str, email: str, browserid: str, random: str) -> str:
    combined = f"{client}-{seval}-{encpwd}-{email}-{browserid}-{random}"
    sha1 = hashlib.sha1()
    sha1.update(combined.encode('utf-8'))
    return sha1.hexdigest()


class TeraboxClient:
    def __init__(self, email: str, password: str, session: aiohttp.ClientSession,
                 cookies: dict[str, str] | None = None, lang: str = 'en') -> None:
        self.email = email
        self.password = password
        self.lang = lang

        self._cookies: TeraboxCookies = self.validate_cookies(cookies)

        self.session = session
        self._base_headers = {
            "User-Agent": USER_AGENT,
            "Origin": BASE_TERABOX_URL,
            "Referer": BASE_TERABOX_URL + "/main",
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
        }

        self.is_vip: bool | None = None
        self._signb: str | None = None
        self._public_key: str | None = None
        self.account: AccountInfo = AccountInfo(account_id=None, display_name='', head_url='')

    @property
    def request_cookies(self) -> dict[str, str]:
        """Get the cookies needed for requests."""
        return {
            **{k: v for k, v in self._cookies.items() if v},
            **({'lang': self.lang} if 'lang' not in self._cookies else {}),
        }

    @staticmethod
    def validate_cookies(cookies: dict[str, Any]):
        required_cookie_keys = list(get_type_hints(TeraboxCookies).keys())
        if cookies is not None:
            missing_keys = [key for key in required_cookie_keys if key not in cookies]
            if missing_keys:
                raise ValueError(f"Missing required cookie keys: {', '.join(missing_keys)}")

        return TeraboxCookies(**cookies) if cookies else TeraboxCookies(**{
            k: '' for k in required_cookie_keys
        })

    @property
    def js_token(self) -> str:
        return self._cookies['jstoken']

    @staticmethod
    async def file_md5(afile:AsyncBufferedReader, chunk_size=1024 * 1024) -> str:
        h = hashlib.md5()
        while True:
            chunk = await afile.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()

    @asynccontextmanager
    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        cookies: dict | None = None,
        clean_cookies: bool = False,
        **kwargs,
    ):
        """Make an HTTP request to the Terabox API."""
        merged_headers = {
            **self._base_headers,
            **(headers or {}),
        }

        merged_cookies = {
            **(self.request_cookies if not clean_cookies else {}),
            **(cookies or {}),
        } or None

        resp = await self.session.request(
            method,
            url,
            headers=merged_headers,
            cookies=merged_cookies,
            **kwargs,
        )
        try:
            yield resp
        finally:
            resp.release()

    async def _locate_upload_host(self) -> str:
        """Locate the upload server."""
        async with self._request(
            'GET',
            "https://d.terabox.com/rest/2.0/pcs/file?method=locateupload",
        ) as response:
            resp_data = await response.json(content_type=None)
            host = resp_data.get("host")
            if not host:
                raise TeraboxApiError(f"Locate upload server failed: {resp_data}")
            return host

    async def _get_home_info(self) -> tuple[str, str]:
        """Get home info to retrieve user details."""
        async with self._request(
            'GET',
            f"{BASE_TERABOX_URL}/api/home/info",
            params={
                "app_id": "250528",
                "web": "1",
                "channel": "dubox",
                "clienttype": "0",
                "jsToken": self.js_token,
            },
            timeout=10,
        ) as response:
            resp_data = await response.json()
            if resp_data.get("errno") != 0:
                raise TeraboxApiError(f"Get home info failed: {resp_data}")
            self._signb = sign_download(resp_data['data']['sign3'], resp_data['data']['sign1'])
        return self._signb, resp_data['data']['timestamp']

    async def _fetch_initial_data(self, url: str = INITIAL_URL, clean_cookies: bool = True) -> dict:
        async with self._request(
            'GET',
            url,
            clean_cookies=clean_cookies,
            timeout=10,
        ) as response:
            text = await response.text()
            tdata_rx = re.compile(r'<script>var templateData = (.*?);</script>')
            js_token_rx = re.compile(r'window.jsToken%20%3D%20a%7D%3Bfn%28%22(.*?)%22%29')

            # {'bdstoken': '', 'pcftoken': '98**20',
            # 'newDomain': {'origin': 'https://www.terabox.com', 'host': 'www.terabox.com',
            # 'domain': 'terabox.com', 'cdn': 'https://s3.teraboxcdn.com',
            # 'isGCP': False, 'originalPrefix': 'www', 'regionDomainPrefix': 'www', 'urlDomainPrefix': 'www'},
            # 'internal': False, 'country': '', 'userVipIdentity': 0, 'uk': 0}
            tdata = json.loads(tdata_rx.search(text).group(1))
            js_token_res = js_token_rx.search(text)
            js_token = js_token_rx.search(text).group(1) if js_token_res else ''

            # rotate auth cookies
            csrf_token = tdata.get('csrf')
            if js_token:
                self._cookies['jstoken'] = js_token
            if csrf_token:
                self._cookies['csrfToken'] = csrf_token

            return {
                'bdstoken': tdata.get('bdstoken', ''),
                'pcftoken': tdata.get('pcftoken', ''),
                'jstoken': js_token,
                'cookies': {
                    **{cookie.key: cookie.value for cookie in self.session.cookie_jar},
                    **({'csrfToken': csrf_token} if csrf_token else {}),
                }
            }

    async def refresh_cookies(self) -> dict:
        return await self._fetch_initial_data(f'{BASE_TERABOX_URL}/main', clean_cookies=False)

    async def get_public_key(self) -> str:
        if self._public_key is None:
            async with self._request(
                'GET',
                f"{BASE_TERABOX_URL}/passport/getpubkey",
                timeout=10,
            ) as response:
                data = await response.json()
                self._public_key = decrypt_aes(data['data']['pp1'], data['data']['pp2'])
        return self._public_key

    async def get_account_id(self):
        """Get the account ID of the current user."""
        if self.account['account_id'] is None:
            async with self._request(
                'GET',
                f"{BASE_TERABOX_URL}/api/check/login",
                timeout=10,
            ) as response:
                data = await response.json()
                if data.get("errno") == -6:
                    raise TeraboxUnauthorizedError('Invalid cookies.')
                if data.get("errno") != 0:
                    raise TeraboxApiError(f"API error: {data}")
                self.account['account_id'] = data.get('uk') or None
        return self.account['account_id']

    async def get_max_file_size(self) -> int:
        """Get the maximum file size allowed for upload."""

        return 4294967296 if await self.check_vip_status() else 21474836479

    async def get_storage_quota(self) -> dict[str, Any]:
            async with self._request(
                'GET',
                f"{BASE_TERABOX_URL}/api/quota?checkexpire=1&checkfree=1",
                timeout=10,
            ) as response:
                data = await response.json()
                if data.get("errno") != 0:
                    raise TeraboxApiError(f"Get quota failed: {data}")

                # {
                #   'errmsg': '',
                #   'errno': 0,
                #   'expire': False,
                #   'extra': {
                #     'init_quota_type': 'permanent_1024g_temp_0g',
                #     'time_limit_quota_expire_time': 0
                #   },
                #   'free': 1099511627776,
                #   'newno': '',
                #   'request_id': 123123123123,
                #   'sbox_used': 0,
                #   'server_time': 1234567890,
                #   'total': 1099511627776,
                #   'used': 5811486
                # }

                data["available"] = data["total"] - data["used"]
                return data

    async def check_vip_status(self) -> bool:
        """Check if the user has VIP status."""

        if self.is_vip is not None:
            return self.is_vip

        async with self._request(
            'GET',
            f"{BASE_TERABOX_URL}/rest/2.0/membership/proxy/user?method=query",
            timeout=10,
        ) as response:
            data = await response.json()
            vip = data["data"]["member_info"]["is_vip"]
            self.is_vip = vip == 1
            return self.is_vip

    # file operations

    async def list_remote_directory(self, remote_dir: str) -> list[FileInfo]:
        """List the contents of a remote directory."""
        async with self._request(
            "GET",
            f"{BASE_TERABOX_URL}/api/list",
            params={
                "app_id": "250528",
                "web": "1",
                "channel": "dubox",
                "clienttype": "5",  # This changed from 0 to 5 in 2025
                "jsToken": self.js_token,
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
                if data["errno"] in {-7, -9}:
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

    async def create_directory(self, remote_dir: str) -> dict:
        """Create a remote directory. Can create nested directories."""
        data = {
            "path": remote_dir,
            "isdir": "1",
            "block_list": "[]",
        }

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/api/create?a=commit",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=10,
        ) as response:
            resp_data = await response.json()
            # {
            #   "category": 6,
            #   "ctime": 1234567890,
            #   "errmsg": "",
            #   "errno": 0,
            #   "from_type": 0,
            #   "fs_id": 1234567890,
            #   "isdir": 1,
            #   "md5": "",
            #   "mtime": 1234567890,
            #   "name": "/test_folder1/subfolder",
            #   "newno": "",
            #   "path": "/test_folder1/subfolder",
            #   "request_id": 12345678901234567,
            #   "server_time": 1234567890,
            #   "size": 0
            # }
            if resp_data.get("errno") == 0:
                return resp_data
            raise TeraboxApiError(f"Directory creation failed: {resp_data}")

    async def _upload_file_chunk(self, upload_host: str, filename: str, filesize: int, remote_path: str,
                                 chunk_md5: str, uploadid: str, partseq: int = 0) -> dict:
        """Upload a file chunk to Terabox."""
        LOGGER.debug(
            "Upload file chunk: %s to %s, size: %d, uploadid: %s",
            filename, remote_path, filesize, uploadid,
        )
        async with aiofiles.open(filename, "rb") as file:
            data = aiohttp.FormData()
            data.add_field("file", AioFilePayload(file, filesize=filesize), filename=filename)

            async with self._request(
                'POST',
                f"https://{upload_host}/rest/2.0/pcs/superfile2?"
                f"method=upload&type=tmpfile&app_id=250528&path={quote_plus(remote_path)}&"
                f"uploadid={uploadid}&partseq={partseq}",
                data=data,
                timeout=15,
            ) as response:
                content = await response.read()
                LOGGER.debug("Upload chunk response: %s", content)

                try:
                    resp = json.loads(content)
                except json.JSONDecodeError:
                    raise TeraboxApiError(f"File upload failed: {content.decode(errors='ignore')}") from None

        if 'error_code' in resp:
            if resp['error_code'] == 31208:
                raise TeraboxContentTypeError(resp['error_msg'])
            raise TeraboxApiError(f"File upload failed: {resp}")

        if resp['md5'] != chunk_md5:
            raise TeraboxChecksumMismatchError("MD5 hash mismatch after file upload.")
        return resp

    async def _precreate_file(self, remote_path: str, md5_list_json: list[str]) -> str:
        data = {
            "app_id": "250528",
            "web": "1",
            "channel": "dubox",
            "clienttype": "0",
            "jsToken": self.js_token,
            "path": remote_path,
            "autoinit": "1",
            "target_path": os.path.dirname(remote_path),
            "block_list": json.dumps(md5_list_json),
        }

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/api/precreate",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{BASE_TERABOX_URL}/main?category=all",
            },
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
        data = {
            "isdir": "0",
            "rtype": "1",
            "app_id": "250528",
            "jsToken": self.js_token,
            "path": remote_path,
            "uploadid": uploadid,
            "target_path": os.path.dirname(remote_path) + '/',
            "size": str(file_size),
            "block_list": json.dumps(md5_list_json),
        }
        LOGGER.debug("Postcreate data: %s", data)

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/api/create",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=10,
        ) as response:
            resp_data = await response.json()
            if resp_data.get("errno") == 0:
                return resp_data
            raise TeraboxApiError(f"File create failed: {resp_data}")

    async def get_files_meta(self, remote_file_list: list[str]) -> dict:
        """Get file metadata from Terabox."""
        await self._get_home_info()
        data = {
            "target": json.dumps(remote_file_list),
            "dlink": "1",
            "origin": "dlna",
        }

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/api/filemetas",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=10,
        ) as response:
            resp_data = await response.json()
            # {
            #   "extent_tinyint4": 0,
            #   "server_mtime": 123456789,
            #   "category": 6,
            #   "isdir": 0,
            #   "videotag": 0,
            #   "dlink": "https://d.terabox.com/file/....&origin=dlna",
            #   "oper_id": 1234567890987,
            #   "play_forbid": 0,
            #   "wpfile": 0,
            #   "local_mtime": 123456789,
            #   "share": 0,
            #   "extent_tinyint3": 0,
            #   "errno": 0,
            #   "local_ctime": 123456789,
            #   "extent_tinyint5": 0,
            #   "owner_type": 0,
            #   "privacy": 0,
            #   "real_category": "",
            #   "path_md5": 0,
            #   "upload_type": 0,
            #   "server_ctime": 123456789,
            #   "tkbind_id": 0,
            #   "extent_tinyint9": 0,
            #   "size": 506,
            #   "md5": "00000000000000000000",
            #   "file_key": "ABCDEF1234567890ABCDEF1234567890",
            #   "fs_id": 123456789012345,
            #   "owner_id": 0,
            #   "extent_int3": 4567890123456,
            #   "path": "/folder/sub/file.txt",
            #   "from_type": 1,
            #   "extent_tinyint2": 0,
            #   "server_filename": "file.txt",
            #   "extent_tinyint1": 0
            # }]
            if any(x.get('errno') == -9 for x in resp_data.get('info', [])):
                raise TeraboxNotFoundError('File not found.')
            if resp_data.get("errno") != 0:
                raise TeraboxApiError(f"Get file metadata failed: {resp_data}")
            return resp_data['info']

    # TODO: investigate the difference with get_files_meta dlink and why this method fails sometimes
    # async def download_file(self, fs_ids: list[str]) -> list[DownloadResponse]:
    #     """Download a file from Terabox."""
    #     signb, timestamp = await self._get_home_info()
    #     data = {
    #         "app_id": "250528",
    #         "web": "1",
    #         "channel": "dubox",
    #         "clienttype": "0",
    #         "jsToken": self.js_token,
    #         "fidlist": json.dumps(fs_ids),
    #         "type": "dlink",
    #         "vip": "2",
    #         "sign": signb,
    #         "timestamp": str(timestamp),
    #         "need_speed": "1",
    #     }
    #
    #     async with self._request(
    #         'GET',
    #         f"{BASE_TERABOX_URL}/api/download",
    #         headers={"Content-Type": "application/x-www-form-urlencoded"},
    #         params=data,
    #         timeout=10,
    #     ) as response:
    #         resp_data = await response.json()
    #         if resp_data.get("errno") == 0:
    #             return resp_data["dlink"]
    #         elif resp_data.get("errno") == 2:
    #             raise TeraboxApiError(f'Invalid timestamp: {resp_data}')
    #         raise TeraboxApiError(f"File download failed: {resp_data}")

    async def upload_file(self, filename: str, destination_path: str) -> dict:
        """Upload a file to Terabox.

        @param filename: a path to the local file to upload
        @param destination_path: path in Terabox to upload
        """

        if not destination_path.startswith('/'):
            destination_path = f'/{destination_path}'

        async with aiofiles.tempfile.TemporaryDirectory() as tmpdir:
            LOGGER.debug("Create tempdir %s", tmpdir)
            file_size = (await aiofiles.os.stat(filename)).st_size
            max_file_size = await self.get_max_file_size()
            if file_size > max_file_size:
                raise ValueError(f"File size {file_size} exceeds maximum allowed size of {max_file_size} bytes.")

            # file chunk names and its md5
            file_chunks_md5 = []
            async with aiofiles.open(filename, mode='rb') as afile:
                file_size = await afile.seek(0, 2)
                await afile.seek(0)

                if file_size > MAX_UNCHUNKED_FILE_SIZE:
                    num_chunks = file_size // CHUNK_SIZE
                    LOGGER.debug("Split file into %d chunks", num_chunks)
                    base_filename = os.path.basename(destination_path)
                    for i in range(num_chunks):
                        chunk_filename = os.path.join(tmpdir, f"{base_filename}.part{i:03d}")
                        written = 0
                        md5 = hashlib.md5()

                        await afile.seek(i * CHUNK_SIZE)
                        async with aiofiles.open(chunk_filename, mode="w+b") as chunk_file:
                            while written < CHUNK_SIZE:
                                bytes_to_read = min(READ_BUF, CHUNK_SIZE - written)
                                data = None
                                if bytes_to_read:
                                    data = await afile.read(bytes_to_read)
                                if not data:
                                    break

                                await chunk_file.write(data)
                                md5.update(data)
                                written += len(data)
                        file_chunks_md5.append((chunk_filename, written, md5.hexdigest()))
                else:
                    file_chunks_md5 = [(filename, file_size, await self.file_md5(afile))]

            LOGGER.debug("Chunks to upload: %s", file_chunks_md5)
            upload_host = await self._locate_upload_host()
            only_md5_list = [md5 for _, _, md5 in file_chunks_md5]
            LOGGER.debug("Call precreate for %s", destination_path)
            try:
                uploadid = await self._precreate_file(destination_path, only_md5_list)
            except TeraboxUnauthorizedError:
                await self.refresh_cookies()
                uploadid = await self._precreate_file(destination_path, only_md5_list)
            LOGGER.debug("Precreate uploadid = %s", uploadid)
            chunk_results = []
            for partseq, (chunk_full_path, chunk_size, chunk_md5) in enumerate(file_chunks_md5):
                resp = await self._upload_file_chunk(
                    upload_host=upload_host,
                    filename=chunk_full_path,
                    filesize=chunk_size,
                    remote_path=destination_path,
                    chunk_md5=chunk_md5,
                    uploadid=uploadid,
                    partseq=partseq,
                )
                chunk_results.append(resp)

            final_resp = await self._postcreate_file(
                remote_path=destination_path,
                uploadid=uploadid,
                file_size=file_size,
                md5_list_json=only_md5_list,
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

        data = {
            "app_id": "250528",
            "web": "1",
            "channel": "dubox",
            "clienttype": "0",
            "jsToken": self.js_token,
            "filelist": json.dumps(remote_paths),
        }

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/api/filemanager",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            params={
                'opera': operation,
                'jsToken': self.js_token,
            },
            data=data,
            timeout=10,
        ) as response:
            resp_data = await response.json()
            if resp_data.get("errno") == 0:
                return resp_data
            raise TeraboxApiError(f"File delete failed: {resp_data}")

    async def delete_files(self, remote_paths: list[str]) -> dict:
        """Delete a file from Terabox.

        @param remote_path: path to the file to delete
        """

        return await self._filemanager('delete', remote_paths)

    async def copy_file(self, remote_src_path: str, remote_dst_path: str) -> dict:
        """Copy a file in Terabox.

        @param remote_src_path: path to the source file
        @param remote_dst_path: path to the destination file
        """

        return await self._filemanager('copy', [{
            "path": remote_src_path,
            "dest": os.path.dirname(remote_dst_path),
            "newname": os.path.basename(remote_dst_path),
        }])

    async def move_file(self, remote_src_path: str, remote_dst_path: str) -> dict:
        """Copy a file in Terabox.

        @param remote_src_path: path to the source file
        @param remote_dst_path: path to the destination file
        """

        return await self._filemanager('copy', [{
            "path": remote_src_path,
            "dest": os.path.dirname(remote_dst_path),
            "newname": os.path.basename(remote_dst_path),
        }])

    async def rename_file(self, remote_src_path: str, new_name: str) -> dict:
        """Rename a file in Terabox.

        @param remote_src_path: path to the source file
        @param new_name: new name for the file
        """

        return await self._filemanager('rename', [{
            "path": remote_src_path,
            "newname": new_name,
        }])

    async def _prelogin(self, email: str) -> tuple[dict, dict]:
        initial_vars = await self._fetch_initial_data()

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/passport/prelogin",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://www.terabox.com/wap/outlogin/emailRegister?tab=1",
                },
            #clean_cookies=True,
            cookies=initial_vars['cookies'],
            data={
                'client': 'web',
                'pass_version': '2.8',
                'clientfrom': 'h5',
                'pcftoken': initial_vars['pcftoken'],
                'email': email,
            },
            timeout=10,
        ) as response:
            data = await response.json()
            if data['code'] != 0:
                raise TeraboxUnauthorizedError(f"Prelogin failed: {data['msg']}")
            return initial_vars, data['data']

    async def do_email_login(self) -> dict:
        initial_vars, prelogin = await self._prelogin(self.email)

        encpass = change_base64_type(encrypt_rsa(self.password, await self.get_public_key(), 2), 2)
        # print('cookies before', {cookie.key: cookie.value for cookie in session.cookie_jar})
        prand = prand_gen(
            client='web',
            seval=prelogin['seval'],
            encpwd=encpass,
            email=self.email,
            browserid=initial_vars['cookies'].get('browserid'),
            random=prelogin['random'],
        )

        async with self._request(
            'POST',
            f"{BASE_TERABOX_URL}/passport/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            clean_cookies=True,
            cookies=initial_vars['cookies'],
            data={
                'client': 'web',
                'pass_version': '2.8',
                'clientfrom': 'h5',
                'pcftoken': initial_vars['pcftoken'],
                'prand': prand,
                'email': self.email,
                'pwd': encpass,
                'seval': prelogin['seval'],
                'random': prelogin['random'],
                'timestamp': prelogin['timestamp'],
            },
            timeout=10,
        ) as response:
            data = await response.json()
            # print('initial data = ', initial_vars)
            # print('cookies after', {cookie.key: cookie.value for cookie in session.cookie_jar})
            # print('login data = ', data)

            # {
            #   'code': 0,
            #   'data': {
            #     'cur_country': 'US',
            #     'displayName': 'USER12345678',
            #     'headUrl': 'https://data.terabox.com/issue/netdisk/ts_ad/group/12345678.png',
            #     'need_protect': 0,
            #     'reg_country': 'US',
            #     'reg_time': 1234567890,
            #     'region_domain_prefix': 'www',
            #     'url_domain_prefix': 'www'
            #   },
            #   'logid': 1234567890,
            #   'msg': ''
            # }
            if data['code'] != 0:
                raise TeraboxUnauthorizedError(f"Login failed: {data['errmsg']}")
            self._cookies.update({cookie.key: cookie.value for cookie in self.session.cookie_jar})
            self.account.update({
                'display_name': data['data']['displayName'],
                'head_url': data['data']['headUrl'],
            })

            # we need to update jstoken after login because it changes to a shorter, authorized one
            async with self._request(
                'GET',
                f"{BASE_TERABOX_URL}/main",
                timeout=10,
            ) as logged_response:
                resp = await logged_response.text()
                js_token_rx = re.compile(r'templateData.*?window.jsToken%20%3D%20a%7D%3Bfn%28%22(.*?)%22%29')
                self._cookies['jstoken'] = js_token_rx.search(resp).group(1)

            return data

    async def ensure_logged_in(self) -> AccountInfo:
        async with self._request('GET', f"{BASE_TERABOX_URL}/passport/get_info", timeout=10) as response:
            data = await response.json()
            # {
            #     'code': 0,
            #     'data': {
            #         'display_name': 'USER1234567',
            #         'head_url': 'https://data.terabox.com/issue/netdisk/ts_ad/group/123456789012345.png',
            #         'region_domain_prefix': 'www',
            #         'url_domain_prefix': 'www'
            #     },
            #     'logid': 1234567890,
            #     'msg': ''
            # }
            if data.get("code") != 0:
                raise TeraboxUnauthorizedError(f"Login failed: {data['msg']}")
            self.account.update(data['data'])
        # rotate cookies on every login
        await self.refresh_cookies()
        return self.account

    async def login(self) -> dict[str, str] | None:
        """Login to Terabox. Returns True if login was performed, False if already logged in."""
        if (
            self._cookies['jstoken'] and
            self._cookies['csrfToken'] and
            self._cookies['browserid'] and
            self._cookies['ndus']
        ):
            try:
                await self.ensure_logged_in()
            except TeraboxUnauthorizedError:
                pass
            else:
                return None
        await self.do_email_login()
        return self._cookies

import asyncio
import hashlib
import io
import json
import os
import re
from io import IOBase
from tempfile import TemporaryDirectory
from typing import NamedTuple, TypedDict, get_type_hints
from urllib.parse import quote_plus

import aiohttp

from .encryption import change_base64_type, decrypt_aes, encrypt_rsa
from .exceptions import (
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


class TeraboxCookies(TypedDict):
    js_token: str  # not a cookie but we store it here for convenience
    csrf_token: str
    browserid: str
    ndus: str


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


def prand_gen(client: str, seval: str, encpwd: str, email: str, browserid: str, random: str) -> str:
    combined = f"{client}-{seval}-{encpwd}-{email}-{browserid}-{random}"
    sha1 = hashlib.sha1()
    sha1.update(combined.encode('utf-8'))
    return sha1.hexdigest()


class TeraBoxClient:
    def __init__(self, email: str, password: str, cookies: dict[str, str] | None = None, lang: str = 'en') -> None:
        self.email = email
        self.password = password
        self.lang = lang

        required_cookie_keys = list(get_type_hints(TeraboxCookies).keys())
        if cookies is not None:
            missing_keys = [key for key in required_cookie_keys if key not in cookies]
            if missing_keys:
                raise ValueError(f"Missing required cookie keys: {', '.join(missing_keys)}")

        self._cookies: TeraboxCookies = TeraboxCookies(**cookies) if cookies else TeraboxCookies(**{
            k: '' for k in required_cookie_keys
        })

        self.is_vip: bool | None = None
        self._public_key: str | None = None
        self._current_user: dict | None = None

    @property
    def request_cookies(self) -> dict[str, str]:
        """Get the cookies needed for requests."""
        return {
            **{k: v for k, v in self._cookies.items() if v},
            **({'lang': self.lang} if 'lang' not in self._cookies else {}),
        }

    @property
    def js_token(self) -> str:
        return self._cookies['js_token']

    @staticmethod
    def file_md5(file: IOBase, chunk_size=1024 * 1024) -> str:
        h = hashlib.md5()
        for chunk in iter(lambda: file.read(chunk_size), b""):
            h.update(chunk)
        return h.hexdigest()

    def get_session(self, headers: dict[str, str] | None = None) -> aiohttp.ClientSession:
        """Get an aiohttp session with the necessary cookies and headers."""
        if headers is None:
            headers = {}
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
        async with self.get_session() as session:
            async with session.get(
                f"{BASE_TERABOX_URL}/api/list",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
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
                            raise TeraboxApiError(f"File upload failed: {content.decode(errors='ignore')}") from None

                        if 'error_code' in resp:
                            if resp['error_code'] == 31208:
                                raise TeraboxContentTypeError(resp['error_msg'])
                            raise TeraboxApiError(f"File upload failed: {resp}")

                        if resp['md5'] != chunk_md5:
                            raise TeraboxChecksumMismatchError("MD5 hash mismatch after file upload.")
                        break
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    # print('... problem, retrying upload ...')
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
                "jsToken": self.js_token,
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
                "jsToken": self.js_token,
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
                "jsToken": self.js_token,
                "filelist": json.dumps(remote_paths),
            }

            async with session.post(
                f"{BASE_TERABOX_URL}/api/filemanager?opera={operation}&jsToken={self.js_token}",
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

    async def get_public_key(self) -> str:
        if self._public_key is None:
            async with aiohttp.ClientSession(
                headers={
                    "User-Agent": USER_AGENT,
                    "Origin": BASE_TERABOX_URL,
                    "Referer": BASE_TERABOX_URL + "/main",
                },
            ) as session:
                async with session.get(
                    f"{BASE_TERABOX_URL}/passport/getpubkey",
                    timeout=10,
                ) as response:
                    data = await response.json()
                    self._public_key = decrypt_aes(data['data']['pp1'], data['data']['pp2'])
        return self._public_key

    @staticmethod
    async def fetch_initial_data() -> dict:
        async with aiohttp.ClientSession(
            headers={
                "User-Agent": USER_AGENT,
                "Origin": BASE_TERABOX_URL,
                "Referer": BASE_TERABOX_URL + "/main",
            },
        ) as session:
            async with session.get(
                f"{BASE_TERABOX_URL}/main",
                timeout=10,
            ) as response:
                text = await response.text()
                tdata_rx = re.compile(r'<script>var templateData = (.*);</script>')
                js_token_rx = re.compile(r'window.jsToken%20%3D%20a%7D%3Bfn%28%22(.*)%22%29')

                # {'bdstoken': '', 'pcftoken': '98**20',
                # 'newDomain': {'origin': 'https://www.terabox.com', 'host': 'www.terabox.com',
                # 'domain': 'terabox.com', 'cdn': 'https://s3.teraboxcdn.com',
                # 'isGCP': False, 'originalPrefix': 'www', 'regionDomainPrefix': 'www', 'urlDomainPrefix': 'www'},
                # 'internal': False, 'country': '', 'userVipIdentity': 0, 'uk': 0}
                tdata = json.loads(tdata_rx.search(text).group(1))
                js_token = js_token_rx.search(text).group(1)

                return {
                    'bdstoken': tdata.get('bdstoken', ''),
                    'pcftoken': tdata.get('pcftoken', ''),
                    'js_token': js_token,
                    'cookies': {cookie.key: cookie.value for cookie in session.cookie_jar},
                }

    @classmethod
    async def _prelogin(cls, email: str) -> tuple[dict, dict]:
        initial_vars = await cls.fetch_initial_data()

        async with aiohttp.ClientSession(
            headers={
                "User-Agent": USER_AGENT,
                "Origin": BASE_TERABOX_URL,
                "Referer": BASE_TERABOX_URL + "/main",
            },
            cookies=initial_vars['cookies'],
        ) as session:
            async with session.post(
                f"{BASE_TERABOX_URL}/passport/prelogin",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
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
                return initial_vars, data['data']

    async def do_email_login(self) -> dict:
        initial_vars, prelogin = await self._prelogin(self.email)

        async with aiohttp.ClientSession(
            headers={
                "User-Agent": USER_AGENT,
                "Origin": BASE_TERABOX_URL,
                "Referer": BASE_TERABOX_URL + "/main",
            },
            cookies=initial_vars['cookies'],
        ) as session:
            encpass = change_base64_type(encrypt_rsa(self.password, await self.get_public_key(), 2), 2)
            # print('cookies before', {cookie.key: cookie.value for cookie in session.cookie_jar})
            prand = prand_gen(
                client='web',
                seval=prelogin['seval'],
                encpwd=encpass,
                email=self.email,
                browserid=initial_vars['cookies']['browserid'],
                random=prelogin['random'],
            )

            async with session.post(
                f"{BASE_TERABOX_URL}/passport/login",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
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
                self._cookies.update({cookie.key: cookie.value for cookie in session.cookie_jar})

                # convert camelCase to snake_case to match passport/get_info response
                rename_map = {
                    'displayName': 'display_name',
                    'headUrl': 'head_url',
                }
                self._current_user = {rename_map.get(k, k): v for k, v in data['data'].items()}

                # we need to update jstoken after login because it changes to a shorter, authorized one
                async with session.get(
                    f"{BASE_TERABOX_URL}/main",
                    timeout=10,
                ) as logged_response:
                    resp = await logged_response.text()
                    js_token_rx = re.compile(r'templateData.*?window.jsToken%20%3D%20a%7D%3Bfn%28%22(.*?)%22%29')
                    self._cookies['js_token'] = js_token_rx.search(resp).group(1)

                return data

    async def ensure_logged_in(self) -> dict:
        async with self.get_session() as session:
            async with session.get(f"{BASE_TERABOX_URL}/passport/get_info", timeout=10) as response:
                data = await response.json()
                if data.get("code") != 0:
                    raise TeraboxUnauthorizedError(f"Login failed: {data['msg']}")
                self._current_user = data['data']
                return self._current_user

    async def login(self) -> dict[str, str] | None:
        """Login to TeraBox. Returns True if login was performed, False if already logged in."""
        if (
            self._cookies['js_token'] and
            self._cookies['csrf_token'] and
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
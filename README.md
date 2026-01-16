
---

## Features

- ⚡ Fully asynchronous (`asyncio`)
- 🌐 HTTP client based on `aiohttp`
- 🔐 Authentication and session handling
- 📂 File and directory operations
- ⬆️ File uploads and downloads

---

## Installation

```sh
pip install aioterabox
```

### Install from source

```bash
git clone https://github.com/devbis/aioterabox.git
cd aioterabox
pip install -e .
```

## Usage

```python
import asyncio
import aiohttp
from aioterabox.api import TeraboxClient


async def main():
    async with aiohttp.ClientSession() as session:
        tb = TeraboxClient(
            session=session,
            email='your_email',
            password='your_password',
            cookies={
                'csrfToken': '...',
                'browserid': '...',
                'ndus': '...',
                'jstoken': '...',
            },
        )
        await tb.login()

        # get quota
        print('quota = ', await tb.get_storage_quota())

        # list files
        files = await tb.list_remote_directory('/path/to/directory')
        print(files)
        
        # create directory
        await tb.create_directory('/remote/directory')

        # upload file
        await tb.upload_file('/home/user/localfile.zip', f'/remote/directory/remotefile.zip')

        # download file
        meta = await tb.get_files_meta(['/remote/directory/remotefile.zip'])[0]
        async with session.get(meta['dlink']) as resp:
            # the link is signed and can be downloaded without authentication
            with open('/tmp/downloadedfile.zip', 'wb') as f:
                while chunk := await resp.content.read(1024):
                    f.write(chunk)

        # rename file  
        await tb.rename_file('/remote/directory/remotefile.zip', 'newname.zip')

        # delete file
        await tb.delete_files(['/remote/directory/newname.zip'])

asyncio.run(main())
```

Though the library supports authentication via username and password, it is highly recommended to use 
session cookies for better reliability. You can obtain the required cookies by logging into TeraBox via 
a web browser and inspecting the cookies set for the domain.

For file operations you should always use absolute paths starting from the root directory `/`.

## Configuration

### Getting the JS Token
To use this tool you need to have a Terabox account and a JS Token key. You can get the session JS Token by logging into your Terabox account and following the sequence of steps below:

1. Open your Terabox cloud.
2. Open the browser's developer tools (F12).<br/>
![Developer tools F12](images/devf12.png)
3. Enable the "Device Toolbar" then click the back arrow to get back to Terabox.<br/> 
![Developer tools F12 "Device Toolbar"](images/devf12devicetoolbar.png) 
![Back Arrow](images/backarrow.png)
4. Go to the "Network" tab.<br/>
![Developer tools F12 Network tab](images/devf12network.png)
5. Select the "XHR" filter.<br/>
![Developer tools F12 XHR filter](images/devf12fetch.png)
6. Click any directory or file in the cloud.
7. Look for any request made to the Terabox cloud URL and click on it.<br/>
![Developer tools F12 request item](images/devf12list.png)
8. Select the "Payload" tab.<br/>
![Developer tools F12 Payload tab](images/devf12payload.png)
9. Look for the jsToken parameter in the list and copy its value.

If you can't find the jsToken parameter, try selecting any other directory or file in the cloud and look for the jsToken parameter in the request payload. Make sure that you have the "XHR" filter selected and that you are looking at the "Payload" tab.


### Getting the cookies values
Additionally to the JS Token, you will need to capture the cookies values. You can get them by following the sequence of steps below:

1. Open your Terabox cloud.
2. Open the browser's developer tools (F12).<br/>
![Developer tools F12](images/devf12.png)
3. Go to the "Application" tab.<br/>
![Developer tools F12 Application tab](images/devf12apptab.png)
4. Select the "Cookies" item in the left panel.<br/>
![Developer tools F12 Cookies tab](images/devf12cookiestab.png)
5. Look for the cookies values and copy them.<br/>
![Developer tools F12 Cookies values](images/devf12cookieval.png)

You will need to copy the csrfToken, browserid, and ndus values.
Once the values are provided the library will refresh the csrfToken and jstoken values on login automatically.

## Requirements

- Python 3.9+
- aiofiles
- aiohttp
- cryptography


## Thanks

https://github.com/seiya-npm/terabox-api for reverse engineering the TeraBox API and JavaScript implementation.
https://github.com/dnigamer/TeraboxUploaderCLI/ for the instructions on obtaining session cookies.

## Disclaimer

This project is not affiliated with or endorsed by TeraBox.
The API behavior may change at any time, which can break compatibility.

Use at your own risk.

## License

Apache License 2.0

See [LICENSE](LICENSE) for more information.

from aiohttp import AsyncIterablePayload


class AsyncFileIterator:
    def __init__(self, file, chunk_size=64 * 1024):
        self._file = file
        self._chunk_size = chunk_size

    async def __aiter__(self):
        while True:
            chunk = await self._file.read(self._chunk_size)
            if not chunk:
                break
            yield chunk


class AioFilePayload(AsyncIterablePayload):
    def __init__(self, file, *, filesize: int | None, chunk_size=64 * 1024, **kwargs):
        async_iterator = AsyncFileIterator(file, chunk_size=chunk_size)
        super().__init__(async_iterator, **kwargs)
        self._size = filesize

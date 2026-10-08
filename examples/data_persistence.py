import asyncio
import pickle
import zlib

from nihomo import Language, NihomoAPI, StarrailInfoParsed


async def main():
    client = NihomoAPI(language=Language.EN)
    data = await client.fetch_user(800333171)

    # Save
    pickle_data = zlib.compress(pickle.dumps(data))
    print(len(pickle_data))
    json_data = data.json(by_alias=True, ensure_ascii=False)
    print(len(json_data))

    # Load
    data_from_pickle = pickle.loads(zlib.decompress(pickle_data))
    data_from_json = StarrailInfoParsed.parse_raw(json_data)
    print(type(data_from_pickle))
    print(type(data_from_json))


asyncio.run(main())

import asyncio
from dlp.dlp_engine import DLPEngine


async def main():
    engine = DLPEngine()

    text = "Tôi muốn hỏi về Project Phoenix và super_secret_token."
    redacted, stats = await engine.redact(text)

    print("Original:", text)
    print("Redacted:", redacted)
    print("Stats:", stats)


if __name__ == "__main__":
    asyncio.run(main())
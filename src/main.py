from loguru import logger
from rich import print

from src.bot.agent import CybersecurityAgent


def main():
    logger.info("Starting Cybersecurity AI Agent Bot")
    bot = CybersecurityAgent()
    print("[bold green]Cybersecurity AI Agent Bot ready.[/bold green]")
    # Demo interactions
    try:
        cve = bot.get_cve_info("CVE-2024-1234")
        print("CVE:", cve)
        report = bot.scan_domain("example.com")
        print("Scan:", report)
        ans = bot.ask_question("What is SQL injection?")
        print("Q&A:", ans)
    except Exception as e:
        logger.exception(e)


if __name__ == "__main__":
    main()

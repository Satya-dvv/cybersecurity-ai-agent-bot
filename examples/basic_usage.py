#!/usr/bin/env python3
"""
Basic Usage Example - Cybersecurity AI Agent Bot

This example demonstrates the core functionality of the Cybersecurity AI Agent Bot
including initialization, basic queries, and simple interactions.

Author: Satya Jagannadh
Project: Cybersecurity AI Agent Bot
"""

import sys
import os

# Add the src directory to the path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.bot.agent import CybersecurityAgent
from src.utils.logger import setup_logger


def basic_initialization():
    """
    Demonstrates basic bot initialization
    """
    print("=" * 60)
    print("Basic Initialization Example")
    print("=" * 60)
    
    # Initialize the bot
    bot = CybersecurityAgent()
    print("✓ Bot initialized successfully")
    print(f"Bot Status: {bot.status}")
    print(f"Available Modules: {', '.join(bot.available_modules)}")
    print()
    
    return bot


def simple_qa_example(bot):
    """
    Demonstrates simple Q&A functionality
    """
    print("=" * 60)
    print("Simple Q&A Example")
    print("=" * 60)
    
    questions = [
        "What is SQL injection?",
        "How does HTTPS work?",
        "What are the main types of malware?"
    ]
    
    for question in questions:
        print(f"\nQuestion: {question}")
        answer = bot.ask_question(question)
        print(f"Answer: {answer}\n")
        print("-" * 60)


def cve_lookup_example(bot):
    """
    Demonstrates basic CVE lookup
    """
    print("=" * 60)
    print("CVE Lookup Example")
    print("=" * 60)
    
    cve_ids = [
        "CVE-2024-1234",  # Example CVE ID
        "CVE-2023-5678",  # Another example
    ]
    
    for cve_id in cve_ids:
        print(f"\nLooking up: {cve_id}")
        cve_info = bot.get_cve_info(cve_id)
        
        if cve_info:
            print(f"Description: {cve_info.get('description', 'N/A')}")
            print(f"Severity: {cve_info.get('severity', 'N/A')}")
            print(f"CVSS Score: {cve_info.get('cvss_score', 'N/A')}")
        else:
            print(f"No information found for {cve_id}")
        
        print("-" * 60)


def bot_status_check(bot):
    """
    Check and display bot status and capabilities
    """
    print("=" * 60)
    print("Bot Status Check")
    print("=" * 60)
    
    print(f"\nBot Version: {bot.version}")
    print(f"Status: {bot.status}")
    print(f"\nAvailable Features:")
    
    features = bot.get_available_features()
    for idx, feature in enumerate(features, 1):
        print(f"  {idx}. {feature}")
    
    print(f"\nAPI Status:")
    api_status = bot.check_api_status()
    for api, status in api_status.items():
        status_icon = "✓" if status else "✗"
        print(f"  {status_icon} {api}")
    
    print()


def interactive_mode(bot):
    """
    Demonstrates interactive mode where user can ask questions
    """
    print("=" * 60)
    print("Interactive Mode")
    print("=" * 60)
    print("\nType your cybersecurity questions below.")
    print("Type 'quit' or 'exit' to end the session.\n")
    
    while True:
        try:
            user_input = input("You: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("\nThank you for using Cybersecurity AI Agent Bot!")
                break
            
            if not user_input:
                continue
            
            # Process the query
            response = bot.process_query(user_input)
            print(f"Bot: {response}\n")
            
        except KeyboardInterrupt:
            print("\n\nSession interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"Error: {str(e)}")


def main():
    """
    Main function to run all examples
    """
    print("\n" + "=" * 60)
    print(" " * 15 + "Cybersecurity AI Agent Bot")
    print(" " * 20 + "Basic Usage Examples")
    print("=" * 60 + "\n")
    
    try:
        # Set up logging
        logger = setup_logger('basic_usage')
        logger.info("Starting basic usage examples")
        
        # Initialize the bot
        bot = basic_initialization()
        
        # Run examples
        print("\n")
        bot_status_check(bot)
        
        print("\n")
        simple_qa_example(bot)
        
        print("\n")
        cve_lookup_example(bot)
        
        # Optional: Interactive mode
        run_interactive = input("\nWould you like to try interactive mode? (y/n): ")
        if run_interactive.lower() in ['y', 'yes']:
            interactive_mode(bot)
        
        logger.info("Basic usage examples completed successfully")
        
    except Exception as e:
        print(f"\nError occurred: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        print("\n" + "=" * 60)
        print(" " * 22 + "Examples Complete")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

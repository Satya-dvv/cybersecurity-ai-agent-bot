"""
Cybersecurity AI Agent Bot - Main Agent Class
Handles user queries and coordinates various cybersecurity modules
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..modules.cve_lookup import CVELookup
from ..modules.vuln_scanner import VulnScanner
from ..modules.qa_engine import QAEngine
from ..modules.doc_analyzer import DocumentAnalyzer
from ..utils.validators import validate_input
from ..utils.logger import setup_logger
from ..config.settings import get_settings
from ..config.prompts import get_prompt

class CybersecurityAgent:
    """
    Main cybersecurity AI agent that handles user queries and coordinates
    various security analysis modules.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the cybersecurity agent.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or get_settings()
        self.logger = setup_logger(__name__, self.config.get('log_level', 'INFO'))
        
        # Initialize modules
        self.cve_lookup = CVELookup(config=self.config)
        self.vuln_scanner = VulnScanner(config=self.config)
        self.qa_engine = QAEngine(config=self.config)
        self.doc_analyzer = DocumentAnalyzer(config=self.config)
        
        # Available commands
        self.commands = {
            'cve': self._handle_cve_query,
            'scan': self._handle_vulnerability_scan,
            'analyze': self._handle_document_analysis,
            'ask': self._handle_qa_query,
            'help': self._handle_help_query
        }
        
        self.logger.info("Cybersecurity Agent initialized successfully")
    
    async def process_query(self, user_query: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Process a user query and return appropriate response.
        
        Args:
            user_query: The user's query string
            context: Optional context information
            
        Returns:
            Dictionary containing response data
        """
        try:
            # Validate input
            if not validate_input(user_query):
                return self._create_error_response("Invalid input provided")
            
            # Parse command from query
            command, params = self._parse_query(user_query)
            
            if command not in self.commands:
                return await self._handle_general_query(user_query, context)
            
            # Execute command
            self.logger.info(f"Processing command: {command}")
            response = await self.commands[command](params, context)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing query: {str(e)}")
            return self._create_error_response(f"An error occurred: {str(e)}")
    
    def _parse_query(self, query: str) -> tuple:
        """
        Parse user query to extract command and parameters.
        
        Args:
            query: User query string
            
        Returns:
            Tuple of (command, parameters)
        """
        query = query.strip().lower()
        parts = query.split()
        
        if not parts:
            return 'help', []
        
        command = parts[0]
        params = parts[1:] if len(parts) > 1 else []
        
        return command, params
    
    async def _handle_cve_query(self, params: List[str], context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Handle CVE lookup queries.
        
        Args:
            params: Query parameters
            context: Optional context
            
        Returns:
            CVE lookup results
        """
        if not params:
            return self._create_error_response("Please provide a CVE ID (e.g., CVE-2023-1234)")
        
        cve_id = params[0].upper()
        
        try:
            result = await self.cve_lookup.lookup_cve(cve_id)
            return {
                'success': True,
                'type': 'cve_lookup',
                'data': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return self._create_error_response(f"CVE lookup failed: {str(e)}")
    
    async def _handle_vulnerability_scan(self, params: List[str], context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Handle vulnerability scanning queries.
        
        Args:
            params: Query parameters (domain/IP)
            context: Optional context
            
        Returns:
            Vulnerability scan results
        """
        if not params:
            return self._create_error_response("Please provide a domain or IP address to scan")
        
        target = params[0]
        
        try:
            result = await self.vuln_scanner.scan_target(target)
            return {
                'success': True,
                'type': 'vulnerability_scan',
                'data': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return self._create_error_response(f"Vulnerability scan failed: {str(e)}")
    
    async def _handle_document_analysis(self, params: List[str], context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Handle document analysis queries.
        
        Args:
            params: Query parameters (file path)
            context: Optional context
            
        Returns:
            Document analysis results
        """
        if not params:
            return self._create_error_response("Please provide a file path to analyze")
        
        file_path = ' '.join(params)
        
        try:
            result = await self.doc_analyzer.analyze_document(file_path)
            return {
                'success': True,
                'type': 'document_analysis',
                'data': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return self._create_error_response(f"Document analysis failed: {str(e)}")
    
    async def _handle_qa_query(self, params: List[str], context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Handle general Q&A queries about cybersecurity.
        
        Args:
            params: Query parameters
            context: Optional context
            
        Returns:
            Q&A response
        """
        if not params:
            return self._create_error_response("Please provide a question")
        
        question = ' '.join(params)
        
        try:
            result = await self.qa_engine.answer_question(question, context)
            return {
                'success': True,
                'type': 'qa_response',
                'data': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return self._create_error_response(f"Q&A processing failed: {str(e)}")
    
    async def _handle_general_query(self, query: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Handle general queries using the Q&A engine.
        
        Args:
            query: User query
            context: Optional context
            
        Returns:
            Response from Q&A engine
        """
        try:
            result = await self.qa_engine.answer_question(query, context)
            return {
                'success': True,
                'type': 'general_response',
                'data': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return self._create_error_response(f"Query processing failed: {str(e)}")
    
    async def _handle_help_query(self, params: List[str], context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Handle help queries.
        
        Args:
            params: Query parameters
            context: Optional context
            
        Returns:
            Help information
        """
        help_text = get_prompt('help_message')
        
        return {
            'success': True,
            'type': 'help',
            'data': {
                'message': help_text,
                'available_commands': list(self.commands.keys())
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def _create_error_response(self, message: str) -> Dict[str, Any]:
        """
        Create standardized error response.
        
        Args:
            message: Error message
            
        Returns:
            Error response dictionary
        """
        return {
            'success': False,
            'type': 'error',
            'data': {
                'error': message
            },
            'timestamp': datetime.now().isoformat()
        }
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Get agent status and module information.
        
        Returns:
            Status information
        """
        return {
            'agent_status': 'active',
            'modules': {
                'cve_lookup': self.cve_lookup.get_status(),
                'vuln_scanner': self.vuln_scanner.get_status(),
                'qa_engine': self.qa_engine.get_status(),
                'doc_analyzer': self.doc_analyzer.get_status()
            },
            'available_commands': list(self.commands.keys()),
            'timestamp': datetime.now().isoformat()
        }
    
    async def shutdown(self):
        """
        Gracefully shutdown the agent and cleanup resources.
        """
        self.logger.info("Shutting down Cybersecurity Agent...")
        
        # Cleanup modules
        await asyncio.gather(
            self.cve_lookup.cleanup(),
            self.vuln_scanner.cleanup(),
            self.qa_engine.cleanup(),
            self.doc_analyzer.cleanup(),
            return_exceptions=True
        )
        
        self.logger.info("Cybersecurity Agent shutdown complete")

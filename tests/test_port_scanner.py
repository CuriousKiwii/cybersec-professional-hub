#!/usr/bin/env python3

import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.port_scanner import PortScanner

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner("127.0.0.1", threads=10)
    
    def test_scanner_initialization(self):
        self.assertEqual(self.scanner.target, "127.0.0.1")
        self.assertEqual(self.scanner.threads, 10)
        self.assertEqual(self.scanner.open_ports, [])
    
    def test_scan_localhost(self):
        open_ports = self.scanner.scan_range(1, 100)
        self.assertIsInstance(open_ports, list)

if __name__ == "__main__":
    unittest.main()

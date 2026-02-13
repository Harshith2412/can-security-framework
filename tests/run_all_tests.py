"""
Run all test suites and generate comprehensive report
"""

import sys
import os
import time
import pytest
from datetime import datetime


def run_all_tests():
    """Run all test suites"""
    
    print("\n" + "="*80)
    print("CAN BUS SECURITY FRAMEWORK - COMPREHENSIVE TEST SUITE")
    print("="*80)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    start_time = time.time()
    
    # Test files to run
    test_files = [
        'test_latency.py',
        'test_resources.py',
        'test_detection.py',
        'test_prevention.py'
    ]
    
    results = []
    
    for test_file in test_files:
        print(f"\n{'='*80}")
        print(f"Running: {test_file}")
        print(f"{'='*80}\n")
        
        test_start = time.time()
        
        # Run test
        exit_code = pytest.main([test_file, '-v', '-s', '--tb=short'])
        
        test_duration = time.time() - test_start
        
        results.append({
            'file': test_file,
            'exit_code': exit_code,
            'duration': test_duration,
            'status': 'PASSED' if exit_code == 0 else 'FAILED'
        })
    
    total_duration = time.time() - start_time
    
    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    for result in results:
        status_symbol = "✓" if result['status'] == 'PASSED' else "✗"
        print(f"{status_symbol} {result['file']:25s} {result['status']:8s} ({result['duration']:.2f}s)")
    
    print("="*80)
    print(f"Total Duration: {total_duration:.2f} seconds")
    print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Overall status
    all_passed = all(r['status'] == 'PASSED' for r in results)
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED")
    else:
        print("\n✗ SOME TESTS FAILED")
        failed = [r['file'] for r in results if r['status'] == 'FAILED']
        print(f"Failed tests: {', '.join(failed)}")
    
    print("="*80 + "\n")
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)

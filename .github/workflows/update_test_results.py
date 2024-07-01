import os
from xml.etree import ElementTree

def update_test_results():
    # Read the XML test report
    test_report = ElementTree.parse('junit/test-results.xml')
    
    # Extract relevant test metrics
    tests = test_report.findall('.//testcase')
    total_tests = len(tests)
    failed_tests = len(test_report.findall('.//failure'))
    passed_tests = total_tests - failed_tests
    
    # Update the README file
    with open('README.md', 'r') as file:
        readme = file.read()
    
    test_results = f"## Test Results\n\nTotal Tests: {total_tests}\nPassed Tests: {passed_tests}\nFailed Tests: {failed_tests}"
    updated_readme = readme.replace('## Test Results', test_results)
    
    with open('README.md', 'w') as file:
        file.write(updated_readme)
    
if __name__ == '__main__':
    update_test_results()
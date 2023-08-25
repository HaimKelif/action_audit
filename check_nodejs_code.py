import os
import subprocess
import sys
import re


LOW = 'low'
MODERATE = 'moderate'
HIGH = 'high'
CRITICAL = 'critical'
 

def run_npd_audit():
    # Run npm audit and return the output.
    process = subprocess.Popen("npm audit", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()

    # Is there an NPM error
    if str(error) != "b''":
        raise Exception('There is an NMP error:\n' + str(error))
    return output


def check_is_particular_string(particular_string, output):
    return str(output).count(str(particular_string)) 

# Returs a string with the titles of NPM output. - all substring between "\n\n" and "\nSeverity". 
def get_titels_from_output(output):
    res = re.findall(r'\\n\\n(.*?)\\nSeverity', str(output))
    return ''.join(res)

# Returns the number of issues with the given severity or higher. 
def check_severity_level(severity, output):
    if str(severity) != LOW and str(severity) != MODERATE and\
        str(severity) != HIGH and str(severity) != CRITICAL:
        return 0
    
    numbr_of_issues = check_is_particular_string("Severity: "+ CRITICAL, output)
    if str(severity) == CRITICAL:
        return numbr_of_issues
    
    numbr_of_issues += check_is_particular_string("Severity: "+ HIGH, output)
    if str(severity) == HIGH:
        return numbr_of_issues
    
    numbr_of_issues += check_is_particular_string("Severity: "+ MODERATE, output)
    if str(severity) == MODERATE:
        return numbr_of_issues
    
    numbr_of_issues += check_is_particular_string("Severity: "+ LOW, output)
    if str(severity) == LOW:
        return numbr_of_issues


def main(particular_string, severity):   
    exception_string = ''

    # Get the output from 'npm audit'.
    output = run_npd_audit() 

    # Check is there the particular substring.
    particular_string_number = check_is_particular_string(particular_string, get_titels_from_output(output))
    if particular_string_number > 0: 
        exception_string += "The given particular string (" + particular_string + ") is in " \
            + str(particular_string_number) + " of the titles of security issues."

    # Check if there are errors that equal or greater then the given severity.
    severity_number = check_severity_level(severity, output)
    if severity_number > 0:
        exception_string += "\nThere are " + str(severity_number) + \
            " security issues with equal or greater severity then " + severity + "."
        
    if exception_string != '':    
        raise Exception(exception_string)

    




# tests:

def test_check_is_particular_string():
    print(check_is_particular_string('a', 'aaa'))
    print(check_is_particular_string('b', 'aaa'))
    print(check_is_particular_string('low', 'aaa low lowest'))
    print(check_is_particular_string('low ', 'aaa low lowest good'))

def test_run_npd_audit():
    process = subprocess.Popen("npm audit", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    print(str(output)) 

def test_get_titels_from_output():
    process = subprocess.Popen("npm audit", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    get_titels_from_output(output)


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        main(str(sys.argv[1]),str(sys.argv[2]))
    else: raise Exception('test as no parameters')
    # test_run_npd_audit()
    # test_get_titels_from_output()
    # test_check_is_particular_string()





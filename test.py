import json


import check_nodejs_code as main


def test_get_severity_list():
    assert main.get_severity_list(main.Severity.LOW.value) == [
        main.Severity.LOW.value,
        main.Severity.MODERATE.value,
        main.Severity.HIGH.value,
        main.Severity.CRITICAL.value,
    ]
    assert main.get_severity_list(main.Severity.MODERATE.value) == [
        main.Severity.MODERATE.value,
        main.Severity.HIGH.value,
        main.Severity.CRITICAL.value,
    ]
    assert main.get_severity_list(main.Severity.HIGH.value) == [
        main.Severity.HIGH.value,
        main.Severity.CRITICAL.value,
    ]
    assert main.get_severity_list(main.Severity.CRITICAL.value) == [
        main.Severity.CRITICAL.value
    ]
    assert main.get_severity_list("XXX") == []
    assert main.get_severity_list("MODERATE") == []


def test_find_severity_in_json():
    output = main.run_npm_audit("npm audit --json")
    assert main.find_severity_in_json(output, main.Severity.CRITICAL.value) == True
    assert main.find_severity_in_json(output, main.Severity.HIGH.value) == True
    assert main.find_severity_in_json(output, main.Severity.MODERATE.value) == True
    assert main.find_severity_in_json(output, main.Severity.LOW.value) == True
    output = json.loads(json.dumps(output).replace("critical", "high"))
    assert main.find_severity_in_json(output, main.Severity.CRITICAL.value) == False
    assert main.find_severity_in_json(output, main.Severity.HIGH.value) == True
    assert main.find_severity_in_json(output, main.Severity.MODERATE.value) == True
    assert main.find_severity_in_json(output, main.Severity.LOW.value) == True
    output = json.loads(json.dumps(output).replace("high", "low"))
    assert main.find_severity_in_json(output, main.Severity.CRITICAL.value) == False
    assert main.find_severity_in_json(output, main.Severity.HIGH.value) == False
    assert main.find_severity_in_json(output, main.Severity.MODERATE.value) == True
    assert main.find_severity_in_json(output, main.Severity.LOW.value) == True


def test_fine_titel_in_json():
    output = main.run_npm_audit("npm audit --json")
    assert main.fine_titels_in_json(output, "reporters") == True
    assert main.fine_titels_in_json(output, "@jest/test-sequencer") == True
    assert main.fine_titels_in_json(output, "@nestjs/common") == True
    assert main.fine_titels_in_json(output, "core") == True
    assert main.fine_titels_in_json(output, "ahwdajdfsdfjhew") == False
    assert main.fine_titels_in_json(output, "re") == True

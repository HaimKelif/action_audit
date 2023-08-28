import json
import check_nodejs_code as main


def test_get_severity_list():
    """
    Test the function get_severity_list
    """
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
    """
    Test the function find_severity_in_json
    @params: --
    @output: --
    """
    output = main.run_npm_audit("npm audit --json")
    if "vulnerabilities" in output:
        output = output["vulnerabilities"]
    assert main.find_severity_in_json(output, main.Severity.CRITICAL.value)
    assert main.find_severity_in_json(output, main.Severity.HIGH.value)
    assert main.find_severity_in_json(output, main.Severity.MODERATE.value)
    assert main.find_severity_in_json(output, main.Severity.LOW.value)
    output = json.loads(json.dumps(output).replace("critical", "high"))
    assert not main.find_severity_in_json(output, main.Severity.CRITICAL.value)
    assert main.find_severity_in_json(output, main.Severity.HIGH.value)
    assert main.find_severity_in_json(output, main.Severity.MODERATE.value)
    assert main.find_severity_in_json(output, main.Severity.LOW.value)
    output = json.loads(json.dumps(output).replace("high", "low"))
    assert not main.find_severity_in_json(output, main.Severity.CRITICAL.value)
    assert not main.find_severity_in_json(output, main.Severity.HIGH.value)
    assert main.find_severity_in_json(output, main.Severity.MODERATE.value)
    assert main.find_severity_in_json(output, main.Severity.LOW.value)


def test_fine_titel_in_json():
    """
    Teat the function find_tutle_in_json
    @params: --
    @output: --
    """
    output = main.run_npm_audit("npm audit --json")
    if "vulnerabilities" in output:
        output = output["vulnerabilities"]
    assert main.fine_titels_in_json(output, "reporters")
    assert main.fine_titels_in_json(output, "@jest/test-sequencer")
    assert main.fine_titels_in_json(output, "@nestjs/common")
    assert main.fine_titels_in_json(output, "core")
    assert not main.fine_titels_in_json(output, "ahwdajdfsdfjhew")
    assert main.fine_titels_in_json(output, "re")


def test_main():
    """
    Teat the function main
    @params: --
    @output: --
    """
    assert main.main("hello!!!", "Xhigh")
    # assert main.main("hell", "low")
    # assert main.main("ce", "high")
    # assert main.main("hello!!!", "high")

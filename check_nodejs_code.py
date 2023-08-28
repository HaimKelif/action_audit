import subprocess
import enum
import typer
from typing import Optional
import json
from typing import Dict, Union


app = typer.Typer()


class Severity(enum.Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


def run_npm_audit(input: str) -> json:
    """
    Runs `npm audit --json` and returns a json
    @params: input: str
    @output: json
    """
    process = subprocess.Popen(
        input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )

    (
        output_bytes,
        error,
    ) = process.communicate()

    if error:
        raise Exception("There is an NMP error:\n" + error.decode())

    output = json.loads(output_bytes)
    return output


def fine_titels_in_json(myjson: json, particular_string: str) -> bool:
    """
    Returns True if the given str is a titel of one of the vulnerabilities.
    @params: myjson: json, particular_string: str
    @output: bool
    """
    for jskey in myjson:
        if particular_string in jskey:
            return True
    return False


def find_severity_in_json(myjson: json, severity: str) -> bool:
    """
    Returns True if the given severity is in the json.vulnerabilities.
    @params: myjson: json, severity: str
    @output: bool
    """
    severity_list = get_severity_list(severity)
    for jskey in myjson:
        for sev in severity_list:
            if "severity" in myjson[jskey]:
                if sev == myjson[jskey]["severity"]:
                    return True
    return False


def get_severity_list(severity: str) -> list[str]:
    """
    Returns list of the severity that equal or higher then the given severity.
    @params: severity: str
    @output: list[str]
    """
    if severity == Severity.LOW.value:
        return [
            Severity.LOW.value,
            Severity.MODERATE.value,
            Severity.HIGH.value,
            Severity.CRITICAL.value,
        ]
    if severity == Severity.MODERATE.value:
        return [Severity.MODERATE.value, Severity.HIGH.value, Severity.CRITICAL.value]
    if severity == Severity.HIGH.value:
        return [Severity.HIGH.value, Severity.CRITICAL.value]
    if severity == Severity.CRITICAL.value:
        return [Severity.CRITICAL.value]
    return []


@app.command()
def main(particular: Optional[str] = None, severity: Optional[str] = None):
    """
    Rase Exception if npm audit is not valid according to the givven severity and str.
    @params: particular: str, severity: str (Typer)
    @output: None
    """
    exception_string = ""

    output = run_npm_audit("npm audit --json")

    if "vulnerabilities" in output:
        output = output["vulnerabilities"]
        if fine_titels_in_json(output, particular):
            exception_string += (
                f"The string ({particular}) is in one of the titles of security issues."
            )
        if find_severity_in_json(output, severity):
            exception_string += (
                f"\nThere are issues with equal or greater severity then {severity}."
            )
        if len(exception_string) != 0:
            raise Exception(exception_string)
    return True


if __name__ == "__main__":
    app()

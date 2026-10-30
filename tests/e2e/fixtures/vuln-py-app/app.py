"""H4 fixture entry: uses insecure-pkg, never unused-pkg."""

from insecure_pkg import connect


def main() -> None:
    print(connect("example.com"))


if __name__ == "__main__":
    main()

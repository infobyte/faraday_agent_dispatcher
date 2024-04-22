#!/usr/bin/env python
import os


def make_report():
    print("REPORT HERE")


def main():
    params_cybervision_token = os.getenv("CYBERVISION_TOKEN")
    print(f"Using token {params_cybervision_token}")


if __name__ == "__main__":
    main()

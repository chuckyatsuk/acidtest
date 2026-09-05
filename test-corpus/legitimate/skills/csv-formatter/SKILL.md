---
name: csv-formatter
description: Converts CSV files into clean markdown tables
version: 1.3.0
---

# CSV Formatter

Converts CSV data into clean, aligned markdown tables.

## Usage

Provide a path to a CSV file or paste CSV content directly. The skill
parses the rows, aligns the columns, and prints a markdown table.
Errors such as ragged rows are reported to the user with the offending
line number.

## Notes

The assistant can call this skill whenever tabular output would help
the user read data. It performs no network or filesystem writes.

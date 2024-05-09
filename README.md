# https-cert-webcrawler

This is barely a webcrawler, it is simply a tool that checks out a list of domains and sees what they respond, focusing on their certificate status.

Right now, I've only built the executable for Windows x64, but it should also work on linux.

## Usage

```
Description:
  Crawls a list of domains read from stdin and reports back some very basic info about each.

Usage:
  WebCrawler [options]

Options:
  -o, --output <output>    The output path for the collected data. []
  -i, --input <input>      Sets an input file instead of reading from stdin (windows friendly) []
  -t, --timeout <timeout>  Timeout in seconds per request. Default is 5 seconds. [default: 5]
  --version                Show version information
  -?, -h, --help           Show help and usage information
```

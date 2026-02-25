# IntelX Credential Scanner

A fast OSINT tool for searching leaked credentials using the Intelligence X API. Searches across multiple breach databases and exports results in TXT, JSON, or CSV formats with built-in deduplication and resume capability.

## Features

✅ **Multi-bucket search** - Searches `leaks.private`, `leaks.public`, `leaks.private.li`, and `pastes`  
✅ **Smart deduplication** - Prevents duplicate credentials across multiple sources  
✅ **Resume capability** - Continue interrupted searches without re-downloading  
✅ **Multiple output formats** - TXT, JSON, or CSV export  
✅ **Rate limiting & retry logic** - Handles API throttling with exponential backoff  
✅ **Credential validation** - Filters out false positives using regex patterns  
✅ **Colored logging** - INFO/DEBUG modes with intuitive color-coded output  
✅ **Regex injection safe** - Properly escapes search patterns  

## Installation

```bash
# Clone the repository
git clone https://github.com/AndreaF17/intelx-credential-scanner.git
cd intelx-credential-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

### API Key Setup

Create a `.env` file in the project root:

```bash
INTELX_API_KEY=your_api_key_here
```

Or pass the API key via command line with `-k` flag.

Get your API key from: [https://intelx.io/](https://intelx.io/)

## Usage

### Basic Usage

```bash
# Search for domain credentials (creates domain.com-creds.txt)
./main.py -t domain.com

# Search with email pattern enabled
./main.py -t domain.com -e

# Specify output format
./main.py -t domain.com -f csv
./main.py -t domain.com -f json
```

### Advanced Options

```bash
# Custom date range (12 months) and max results
./main.py -t domain.com -r 12 -m 500

# Enable debug logging
./main.py -t domain.com -d

# Custom output file
./main.py -t domain.com -o results.txt

# Provide API key via CLI
./main.py -t domain.com -k YOUR_API_KEY
```

### Full Command Reference

```
usage: main.py [-h] -t TARGET [-m MAXRESULTS] [-k APIKEY] [-o OUTPUT]
               [-f {txt,json,csv}] [-r RANGE] [-d] [-e]

Search for leaked credentials

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        The target domain to search for
  -m MAXRESULTS, --maxresults MAXRESULTS
                        Maximum number of results per bucket (default: 100)
  -k APIKEY, --apikey APIKEY
                        IntelX API key
  -o OUTPUT, --output OUTPUT
                        Output file to save the results
  -f {txt,json,csv}, --format {txt,json,csv}
                        Output format (default: txt)
  -r RANGE, --range RANGE
                        Search range in months (default: 6)
  -d, --debug           Enable DEBUG logging
  -e, --email           Also search for @domain pattern
```

## Output Formats

### TXT Format (default)
```
https://app.example.com:user@example.com:Password123!
https://portal.example.com:admin@example.com:SecurePass456
```

### JSON Format
```json
[
  {
    "url": "https://app.example.com",
    "email": "user@example.com",
    "password": "Password123!",
    "source": "breach_2024_leak.txt"
  }
]
```

### CSV Format
```csv
url,email,password,source
https://app.example.com,user@example.com,Password123!,breach_2024_leak.txt
```

## Resume Capability

If the script is interrupted, simply re-run the same command. It will:
1. Load existing credentials from the output file
2. Skip duplicates automatically
3. Append only new findings

```bash
# First run (interrupted)
./main.py -t domain.com

# Resume (continues where it left off)
./main.py -t domain.com
```

## Logging

**INFO mode (default):**
- Search parameters
- Found credentials
- Total unique count

**DEBUG mode (`-d` flag):**
- API initialization details
- Per-bucket search results
- Individual leak processing
- Duplicate detection
- FILE_VIEW retry attempts

## Best Practices

1. **Start with small date ranges** - Test with `-r 1` for one month
2. **Use email search judiciously** - `-e` flag increases API calls significantly
3. **Monitor rate limits** - The script includes 0.5s delays between requests
4. **Check output regularly** - Use resume capability for large searches
5. **Secure your API key** - Never commit `.env` file to version control

## Limitations

- IntelX API rate limits apply
- Free tier has limited daily requests
- Password validation requires `email:password` format
- TLD must be 2+ characters for credential matching

## Troubleshooting

**"API key is required" error:**
- Check `.env` file exists and contains `INTELX_API_KEY=...`
- Or provide key with `-k` flag

**No credentials found:**
- Try enabling email search with `-e`
- Increase date range with `-r 12`
- Enable debug mode with `-d` to see what's being searched
- Verify the domain exists in IntelX database

**Rate limit errors:**
- Script automatically retries with exponential backoff
- Reduce `maxresults` with `-m 50`
- Consider spreading searches over multiple days

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Disclaimer

This tool is for **authorized security assessments only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

The authors assume no liability for misuse of this tool.

## Credits

- Built with [Intelligence X API](https://intelx.io/)
- Uses [intelxapi](https://github.com/IntelligenceX/SDK/tree/master/Python) Python SDK

## Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing issues for solutions

---

**Star ⭐ this repo if you find it useful!**

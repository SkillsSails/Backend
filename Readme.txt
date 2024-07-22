# LinkedIn Job Scraper

## Description
This project scrapes job listings from LinkedIn based on a specified search URL. It collects the job titles, company names, and job links, and saves this data into CSV files.

## Setup and Installation

### Prerequisites
- Python 3.x
- Selenium
- ChromeDriver

### Installation
1. Install the required Python packages:
pip install selenium pandas

2. Download ChromeDriver from [here](https://sites.google.com/a/chromium.org/chromedriver/downloads) and place it in a suitable directory. Update the path in the script accordingly.

## Usage
1... Update the `url1` variable with the desired LinkedIn job search URL.
2... Run the script to start the scraping process:
```python
python your_script_name.py

3 . The script will save two CSV files in the current directory:
linkedin.csv: Contains job titles and company names.
linkedinlinks.csv: Contains links to the job listings.
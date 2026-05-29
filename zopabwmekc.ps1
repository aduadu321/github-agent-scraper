# Quick hunt: find secrets, validate, generate report
Set-Location C:\Users\aduad\tools\github-scraper
python pipeline.py --mode hunt --quick --category all
Start-Process output\report.html

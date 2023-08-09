from selenium import webdriver

# Set the URL of the website you want to capture
website_url = 'https://www.vg.no'

# Initialize the WebDriver options
options = webdriver.FirefoxOptions()
options.add_argument('-headless')  # Run in headless mode (no visible browser window)

try:
    # Initialize the WebDriver with options
    driver = webdriver.Firefox(executable_path='/usr/local/bin/geckodriver', options=options)
    
    # Load the website
    driver.get(website_url)

    # Take a screenshot
    screenshot_filename = 'website_screenshot.png'
    driver.save_screenshot(screenshot_filename)
    print(f'Screenshot saved as {screenshot_filename}')
except Exception as e:
    print(f'An error occurred: {str(e)}')
finally:
    if 'driver' in locals():
        # Close the WebDriver
        driver.quit()

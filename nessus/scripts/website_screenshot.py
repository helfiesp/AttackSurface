from selenium import webdriver

# Set the path to the WebDriver executable (e.g., chromedriver)
webdriver_path = '/usr/local/bin/chromedriver'

# Set the URL of the website you want to capture
website_url = 'vg.no'

# Initialize the WebDriver
options = webdriver.ChromeOptions()
options.add_argument('--headless')  # Run in headless mode (no visible browser window)
driver = webdriver.Chrome(executable_path=webdriver_path, options=options)

try:
    # Load the website
    driver.get(website_url)

    # Take a screenshot
    screenshot_filename = 'website_screenshot.png'
    driver.save_screenshot(screenshot_filename)
    print(f'Screenshot saved as {screenshot_filename}')
except Exception as e:
    print(f'An error occurred: {str(e)}')
finally:
    # Close the WebDriver
    driver.quit()

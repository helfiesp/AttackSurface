from selenium import webdriver

# Set the path to the WebDriver executable (chromedriver)
chromedriver_path = '/usr/local/bin/chromedriver'

# Set the URL of the website you want to capture
website_url = 'https://www.vg.no'

try:
    # Initialize the WebDriver
    driver = webdriver.Chrome(chromedriver_path)
    
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
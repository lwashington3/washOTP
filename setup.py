from setuptools import setup


with open("README.md", 'r') as f:
	long_description = f.read()


project_name = "washOTP"
git_url = f"https://github.com/lwashington3/{project_name}"


setup(
	name="washOTP",
	version="1.1.2",
	author="Len Washington III",
	author_email="l.washingtoniii.27@gmail.com",
	description="Basic OTP generator",
	include_package_data=True,
	long_description=long_description,
	long_description_content_type="test/markdown",
	url=git_url,
	project_urls={
		"Bug Tracker": f"{git_url}/issues"
	},
	license="MIT",
	packages=[project_name],
	install_requires=["colors @ git+https://github.com/lwashington3/colors", "qrcode[pil]"],
	entry_points={
		"console_scripts": [f"{project_name}={project_name}.command_line:main"]
	},
	classifiers=[
		"Programming Language :: Python :: 3.9",
		"Programming Language :: Python :: 3.10",
		"Programming Language :: Python :: 3.11"
	]
)

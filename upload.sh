# pip install wheel
# pip install twine
python setup.py bdist_wheel --universal
twine upload dist/*
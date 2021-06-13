# firmanalyse

this repo contains a python script to extract iformation from a binary file, with the help of:
- binwalk
- shutil
and output's information on terminal and in Json format, using:
- terminaltables
- json

The requrements are,
-readelf,
-scanelf,


##Information Needed:
- OS Version.
- Processor Architecture.
- List of Binary files with Name, Path, Attributes & their Permissions.
- Binary file analysis. (EXC or Lib{static/dynamic}, PIE)

##Working on:
- How to find CVE's based on binary file.

##Worked on:
- Write a extractor code using binwalk.
- automate Information gathering.
- collect and format the information.
- add Json feature.

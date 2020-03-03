Log analyzer
========
This project is intended for analyzing the nginx log. 
Work with `gzip` and `plant` format.
Parses the last file by date in the file name

Requirements
-----------
* Nginx log must be match this format:
    ```
    $remote_addr $remote_user $http_x_real_ip [$time_local] "$request" 
    $status $body_bytes_sent "$http_referer" 
    "$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER"
    $request_time'
    ```
* Log file must be named as `nginx-access-ui.log-20170601.log` where `20100601` - it's date create log
* To run test install pytest
    ```shell script
    pip install -r requiments.txt
    ```
How install
---------
* Download project
```shell script
git clone <!set link>
```

Usage example
--------
* Run main.py
    ```shell script
    python main.py
    ```
* Run test:
    ```shell script
    python -m pytest
    ```



Settings
-----------
Project has default settings. You can set new settings in file `config.ini` or a configuration using a custom path and them run `main.py` 
with options `--config <path to config.ini`.

Settings:

|Name |Description|Default value|
|----|----|----|
| BASE_DIR|root folder with the project| .|
|LOG_DIR| Folder where nginx logs are located| `BASE_DIR`/logs/nginx
|REPORT_DIR| Folder to save the report to| `BASE_DIR`/report_dir
|REPORT_SIZE| how many URLs with the maximum response time to leave in the report. Calculated by the sum of ' $request_time`| 1000
|TEMPLATE| Folder with the template for the report|`BASE_DIR`/template/report.html 
|failure_perc| max percent failure parced time_sum to generate report|50
|LOG_FILE| File log. if set `None` log will write `stdin`| None
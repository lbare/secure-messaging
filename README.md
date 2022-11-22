# SENG-360-GROUP-1

Secure Messaging Service

# Test Environment Setup

## 1. Create ```credentials.txt``` inside  ```/src/``` and add a username such as the following

```
username:Test_id
```

The username set here needs to match the username set in [test_client.py](https://gitlab.csc.uvic.ca/courses/2022091/SENG360_COSI/assignments/ebertc/seng-360-group-1/-/blob/main/src/test_client.py) to send a message in the correct format

```python
user = "Test_id"
 ```

## 2. Add loopback IP to ```config-file.txt``` and ```server.py```

The port number should stay the same in [config-file.txt](https://gitlab.csc.uvic.ca/courses/2022091/SENG360_COSI/assignments/ebertc/seng-360-group-1/-/blob/main/src/config-file.txt) but with the loopback IP it should look like the following

```
ip:127.0.0.1
port:9999
```

while [server.py](https://gitlab.csc.uvic.ca/courses/2022091/SENG360_COSI/assignments/ebertc/seng-360-group-1/-/blob/main/src/server.py) will change from

```python
address = (socket.gethostbyname(socket.gethostname()), 9999)
```

to

```python
address = ('127.0.0.1', 9999)
```

## 3. Run ```server.py``` in a terminal followed by ```test_client.py``` in another

If all is setup correctly and a connection is made you should see the following

```bash
> python3 server.py
172.21.0.1
('127.0.0.1', 51335)
```

```bash
> python3 test_client.py
('127.0.0.1', 9999)
```
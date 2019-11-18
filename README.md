# Intro

This repo is a demo implementation of [AMBI](https://datatracker.ietf.org/doc/draft-jholland-mboned-ambi/), built on [python-asyncio-taps](https://github.com/fg-inet/python-asyncio-taps).

# Usage

This will provide manifests over TCP on 127.0.0.1:8080:

~~~
python ambiGen.py -s 23.212.185.7 -g 232.1.1.1 -p 5001 -m 15 -a shake-128 -o 8080
~~~

This will receive and check the integrity of multicast packets against the provided manifests:
~~~
python ambiFramer.py --ssm-address 23.212.185.7 --ssm-port 1005 --group-address 232.1.1.1 --group-port 5001 --remote-ambi-address 127.0.0.1 --remote-ambi-port 8080
~~~
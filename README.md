## weblogic-gadget-probe

- modified from [ysoserial](https://github.com/frohoff/ysoserial)
- added dns gadget probe for weblogic 
    - generate dns callback payload and packed into t3 protocol format (using cve-2018-2628 script)
- How to use
    - `mvn clean package -DskipTests` (Build ysoserial with my probe payload)
    - `python auto.py wlsserver.com 7001 black.list mydnslog.tw`

![](https://github.com/w181496/weblogic-gadget-probe/blob/master/demo.png)

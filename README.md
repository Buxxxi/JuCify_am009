# JuCify

Unifying Android code for enhanced static analysis.

## Getting started

### Docker image

- mount platforms directory into container, eg: `/platforms`
- mount folder containing apk into container, eg: `/root/apps`
- entrypoint is `/root/JuCify/runTool.sh` (usage see `JuCify\scripts\main.sh`), specify mounted platforms dir after `-p`, full apk path after `-f`(can't use relative path). specify `-t` for taint analysis.
- intermediate files and folders include `APK_NAME/ APK_NAME_result/ APK_NAME.native.log APK_NAME.flow.log`. specify `-c` in cmdline to automatically delete two folders.

eg:
```
docker run --rm -v C:\Users\xxx\AppData\Local\Android\Sdk\platforms\:/platforms -v C:\Users\xxx\JuCify\benchApps\:/root/apps warrenwjk/jucify -p /platforms -f /root/apps/getter_imei.apk -t -c
```

or override entrypoint to execute preferred script
```
docker run --rm -v C:\Users\xxx\AppData\Local\Android\Sdk\platforms\:/platforms -v C:\Users\xxx\JuCify\benchApps\:/root/apps --entrypoint /bin/bash warrenwjk/jucify /root/JuCify/runTool.sh -p /platforms -f /root/apps/getter_imei.apk -t -c
```

nativediscloser submodule is modified, see commits in: https://github.com/am009/nativediscloser/tree/6897c58_docker

### Downloading the tool

<pre>
git clone https://github.com/JordanSamhi/JuCify.git
</pre>

### Installing the tool

<pre>
cd JuCify
mvn clean install
</pre>

### Issues

If you stumble upon a stack overflow error while building JuCify, increase memory available with this command:

<pre>
export MAVEN_OPTS=-Xss32m
</pre>

Then, try to rebuild.

### Using the tool

<pre>
java -jar JuCify/target/JuCify-0.1-jar-with-dependencies.jar <i>options</i>
</pre>

Options:

* ```-a``` : The path to the APK to process.
* ```-p``` : The path to Android platofrms folder.
* ```-f``` :  Provide paths to necessary files for native reconstruciton.
* ```-r``` : Print raw results.
* ```-ta``` : Perform taint analysis.
* ```-c``` : Export call-graph to text file.
* ```-e``` : Export call-graph to dot format.

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details

## Contact

For any question regarding this study, please contact us at:
[Jordan Samhi](mailto:jordan.samhi@uni.lu)

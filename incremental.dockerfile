FROM jucify-tmp
# docker run -it --entrypoint /bin/bash --name jucifytmp jucify
# docker commit -m "enable flowdroid logging" jucifytmp jucify-tmp
ENTRYPOINT ["/bin/bash", "/root/JuCify/runTool.sh"]
CMD ["-p", "/platforms", "-f", "/root/apps/app.apk", "-t", "-c"]
# docker build -f ./incremental.dockerfile -t jucify:fix1 .


## other commands
# docker image rm jucify-tmp
# docker image rm jucify:fix1
# docker start -i jucifytmp
# docker cp ./src/main/resources/log4j.xml jucifytmp:/root/JuCify/
# docker cp /home/user/ns/dev/jucify/src/main/resources/SourcesSinks.txt jucifytmp:/root/JuCify/src/main/resources/SourcesSinks.txt
# ./build.sh
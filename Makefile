default:
	find -name "*.java" > sources.txt
	javac @sources.txt
clean:
	find src -name "*.class" -type f -delete
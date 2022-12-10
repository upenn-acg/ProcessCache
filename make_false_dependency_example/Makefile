
TimeCmd=/usr/bin/time --format "%E min:sec wall-clock time"
PCCmd=../target/debug/process_cache

one.bin: one.c two.c
	gcc -Wall one.c -o $@

clean:
	rm -f one.bin

justmake:
	@echo "\n  ** build with standalone make **\n"
	@make clean
	@echo "\n  * initial build, should be slow\n"
	$(TimeCmd) make
	@echo "\n  * update false dependency\n"
	touch two.c
	@echo "\n  * second build, still slow\n"
	$(TimeCmd) make

pcmake:
	@echo "\n  ** build with make + ProcessCache **\n"
	@make clean
	rm -rf cache/
	@echo "\n  * initial build, should be slow\n"
	$(TimeCmd) $(PCCmd) make
	@echo "\n  * NOP build to populate cache\n"
	$(TimeCmd) $(PCCmd) make
	@echo "\n  * update false dependency\n"
#	echo "a" >> two.c
	touch two.c
	@echo "\n  * third build, should be fast\n"
	$(TimeCmd) $(PCCmd) make

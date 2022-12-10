
TimeCmd=/usr/bin/time --format "%E min:sec wall-clock time"
PCCmd=../target/debug/process_cache

one.bin: one.c two.c
	gcc -Wall one.c -o $@

clean:
	rm -f one.bin

justmake:
	@echo "  ** build with standalone make **"
	@make clean
	@echo "  * initial build, should be slow"
	$(TimeCmd) make
	@echo "  * update false dependency"
	touch two.c
	@echo "  * second build, still slow"
	$(TimeCmd) make

pcmake:
	@echo "  ** build with make + ProcessCache **"
	@make clean
	rm -rf cache/
	@echo "\n  * initial build, should be slow\n"
	$(TimeCmd) $(PCCmd) make
	@echo "\n  * NOP build to populate cache\n"
	$(TimeCmd) $(PCCmd) make
	@echo "\n  * update false dependency\n"
	touch two.c
	@echo "\n  * third build, should be fast\n"
	$(TimeCmd) $(PCCmd) make

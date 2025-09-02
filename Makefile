FLAGS = -Wall -Wextra -I./include
TEST_FLAGS = $(FLAGS) # test-specific flags

ifeq ($(OS),Windows_NT)
GTEST_LIBS = -L/mingw64/lib -lgtest -lbcrypt
PLATFORM_LIBS = -lbcrypt
else
GTEST_LIBS = -pthread /usr/lib/x86_64-linux-gnu/libgtest.a /usr/lib/x86_64-linux-gnu/libgtest_main.a
PLATFORM_LIBS =
endif

build_all: clean build_test build_debug build_profile build_release build_speed_test

build_test:
	docker-compose exec aes g++ $(FLAGS) -g -pthread ./src/aes.cpp ./src/aes_utils.cpp ./tests/tests.cpp /usr/lib/libgtest.a -o bin/test

build_debug:
	docker-compose exec aes g++ $(FLAGS) -g ./src/aes.cpp ./src/aes_utils.cpp ./dev/main.cpp -o bin/debug

build_profile:
	docker-compose exec aes g++ $(FLAGS) -pg ./src/aes.cpp ./src/aes_utils.cpp ./dev/main.cpp -o bin/profile

build_speed_test:
	docker-compose exec aes g++ $(FLAGS) -O2 ./src/aes.cpp ./src/aes_utils.cpp ./speedtest/main.cpp -o bin/speedtest

build_release:
	docker-compose exec aes g++ $(FLAGS) -O2 ./src/aes.cpp ./src/aes_utils.cpp ./dev/main.cpp -o bin/release



test:
	docker-compose exec aes bin/test

debug:
	docker-compose exec aes bin/debug

profile:
	docker-compose exec aes bin/profile

release:
	docker-compose exec aes bin/release

speed_test:
	docker-compose exec aes bin/speedtest

style_fix:
	docker-compose exec aes bash -c "clang-format -i src/*.cpp include/aescpp/*.hpp tests/*.cpp"


clean:
	docker-compose exec aes rm -rf bin/*


workflow_build_test: ; g++ $(FLAGS) $(CXXFLAGS) -c ./src/aes.cpp -o bin/aes.o; g++ $(FLAGS) $(CXXFLAGS) -c ./src/aes_utils.cpp -o bin/aes_utils.o; g++ $(TEST_FLAGS) $(CXXFLAGS) -g bin/aes.o bin/aes_utils.o ./tests/tests.cpp $(GTEST_LIBS) -o bin/test

workflow_build_speed_test:
	g++ $(FLAGS) -O2 ./src/aes.cpp ./src/aes_utils.cpp ./speedtest/main.cpp $(PLATFORM_LIBS) -o bin/speedtest


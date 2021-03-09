//std
#include <iostream>
#include <string>

#include <gtest/gtest.h>
#include "all_tests.h"

int main(int _argc, char** _argv)
{
	testing::InitGoogleTest(&_argc, _argv);

	return RUN_ALL_TESTS();
}
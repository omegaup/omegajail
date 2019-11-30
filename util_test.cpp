#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "util.h"

TEST(UtilTest, StringPrintf) {
  EXPECT_EQ(StringPrintf("%s %s", "hello", "world"), "hello world");
  EXPECT_EQ(StringPrintf("%d %d", 0, 1), "0 1");
}

TEST(UtilTest, StringSplit) {
  EXPECT_EQ(StringSplit("hello:world", ':'),
            (std::vector<std::string>{"hello", "world"}));
}

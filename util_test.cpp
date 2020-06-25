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

TEST(UtilTest, StringSplitByChar) {
  EXPECT_EQ(StringSplit("hello:world", ':'),
            (std::vector<std::string>{"hello", "world"}));
}

TEST(UtilTest, StringSplitByAnyChar) {
  EXPECT_EQ(StringSplit("hey,hello:world", ByAnyChar(",:")),
            (std::vector<std::string>{"hey", "hello", "world"}));
}

TEST(UtilTest, StringJoin) {
  EXPECT_EQ(StringJoin({"hello", "world"}, ":"), "hello:world");
}

TEST(CleanTest, AlreadyClean) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"abc", "abc"},
           {"abc/def", "abc/def"},
           {"a/b/c", "a/b/c"},
           {".", "."},
           {"..", ".."},
           {"../..", "../.."},
           {"../../abc", "../../abc"},
           {"/abc", "/abc"},
           {"/", "/"},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(CleanTest, EmptyIsCurrentDir) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"", "."},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(CleanTest, RemoveTrailingSlash) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"abc/", "abc"},
           {"abc/def/", "abc/def"},
           {"a/b/c/", "a/b/c"},
           {"./", "."},
           {"../", ".."},
           {"../../", "../.."},
           {"/abc/", "/abc"},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(CleanTest, RemoveDoubledSlash) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"abc//def//ghi", "abc/def/ghi"},
           {"//abc", "/abc"},
           {"///abc", "/abc"},
           {"//abc//", "/abc"},
           {"abc//", "abc"},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(CleanTest, RemoveDotElements) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"abc/./def", "abc/def"},
           {"/./abc/def", "/abc/def"},
           {"abc/.", "abc"},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(CleanTest, RemoveDotDotElements) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"abc/def/ghi/../jkl", "abc/def/jkl"},
           {"abc/def/../ghi/../jkl", "abc/jkl"},
           {"abc/def/..", "abc"},
           {"abc/def/../..", "."},
           {"/abc/def/../..", "/"},
           {"abc/def/../../..", ".."},
           {"/abc/def/../../..", "/"},
           {"abc/def/../../../ghi/jkl/../../../mno", "../../mno"},
           {"/../abc", "/abc"},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(CleanTest, Combinations) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"abc/./../def", "def"},
           {"abc//./../def", "def"},
           {"abc/../../././../def", "../../def"},
       }) {
    EXPECT_EQ(Clean(s), expected);
  }
}

TEST(DirnameTest, TrailingSlash) {
  for (const auto& [s, expected] :
       std::vector<std::pair<std::string_view, std::string>>{
           {"/abc/def/", "/abc"},
           {"/abc/", "/"},
           {"/", "/"},
       }) {
    EXPECT_EQ(Dirname(s), expected);
  }
}

TEST(DirnameTest, Levels) {
  for (const auto& [level, expected] :
       std::vector<std::pair<size_t, std::string>>{
           {1, "/abc/def/ghi"},
           {2, "/abc/def"},
           {3, "/abc"},
           {4, "/"},
           {5, "/"},
       }) {
    EXPECT_EQ(Dirname("/abc/def/ghi/jkl", level), expected)
        << "for level " << level;
  }
}

TEST(DirnameTest, RelativeLevels) {
  for (const auto& [level, expected] :
       std::vector<std::pair<size_t, std::string>>{
           {1, "abc/def/ghi"},
           {2, "abc/def"},
           {3, "abc"},
           {4, "./"},
           {5, "../"},
           {6, "../../"},
       }) {
    EXPECT_EQ(Dirname("abc/def/ghi/jkl", level), expected)
        << "for level " << level;
  }
}

TEST(PathJoinTest, UseComponentAsIs) {
  for (const auto& [path, component, expected] :
       std::vector<std::tuple<std::string_view, std::string_view, std::string>>{
           {"abc", "/def", "/def"},
           {"/abc", "/def", "/def"},
           {"", "def", "def"},
       }) {
    EXPECT_EQ(PathJoin(path, component), expected)
        << "for '" << path << "', '" << component << "'";
  }
}

TEST(PathJoinTest, DoubleSlash) {
  for (const auto& [path, component, expected] :
       std::vector<std::tuple<std::string_view, std::string_view, std::string>>{
           {"/abc/", "def/", "/abc/def"},
       }) {
    EXPECT_EQ(PathJoin(path, component), expected)
        << "for '" << path << "', '" << component << "'";
  }
}

TEST(PathJoinTest, CleansAfterwards) {
  for (const auto& [path, component, expected] :
       std::vector<std::tuple<std::string_view, std::string_view, std::string>>{
           {"/abc/", "def/", "/abc/def"},
           {"/abc/.", "./def", "/abc/def"},
           {"/abc/", "../def", "/def"},
       }) {
    EXPECT_EQ(PathJoin(path, component), expected)
        << "for '" << path << "', '" << component << "'";
  }
}

TEST(PathJoinTest, MultipleArgs) {
  EXPECT_EQ(PathJoin("a", "b", "c"), "a/b/c");
  EXPECT_EQ(PathJoin("a", "/b", "c"), "/b/c");
}

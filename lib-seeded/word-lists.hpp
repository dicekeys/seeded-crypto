#pragma once

#ifndef EMSCRIPTEN
 #pragma warning( disable : 26812 )
#endif
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "externally-generated/derivation-parameters.hpp"

const std::vector<std::string>& getWordList(DerivationOptionsJson::WordList wordListName);
#include "word-lists.hpp"

#include "externally-generated/derivation-parameters.hpp"
#include "externally-generated/word-lists/EN_512_words_5_chars_max_ed_4_20200917.hpp"
#include "externally-generated/word-lists/EN_1024_words_6_chars_max_ed_4_20200917.hpp"

const std::vector<std::string>& getWordList(RecipeJson::WordList wordListName) {
	return
    wordListName == RecipeJson::WordList::EN_512_words_5_chars_max_ed_4_20200917 ?
	    EN_512_words_5_chars_max_ed_4_20200917 :
    wordListName == RecipeJson::WordList::EN_1024_words_6_chars_max_ed_4_20200917 ?
  	  EN_1024_words_6_chars_max_ed_4_20200917 :
			// default
			EN_512_words_5_chars_max_ed_4_20200917;
}

#include "user.h"
#include "log.h"
#include "rule.h"

int main(int argc, char *argv[]) {
    if (argc == 1){
        printf("Error: Please provide arguments\n");
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "show_rules") == 0){
            if (show_rules() == 0){
                printf("Error: show_rules didn't work\n");
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }

        if (strcmp(argv[1], "show_log") == 0){
            if (show_log() == 0){
                printf("Error: show_log didn't work\n");
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[1], "clear_log") == 0){
            if (clear_log() == 0){
                printf("Error: clear_log didn't work\n");
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }

    }
    if (argc == 3) {
        if (strcmp(argv[1], "load_rule") == 0){
            if (load_rules(argv[2]) == 0){
                printf("Error: load_rule didn't work\n");
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }
    }
    if (argc > 3){
        printf("Error: Too many arguments\n");
        return EXIT_FAILURE;
    }

    return 0; // Return success if no errors occurred
}

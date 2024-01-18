#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define PATH "/sys/class/Sysfs_class/Sysfs_class_packet_statistics/sysfs_att" // Path to the sysfs file.
#define UINT_SIZE sizeof(unsigned int) // Size of unsigned int in bytes so we can read it from the sysfs file (2 unsigned ints in the file).



int main(int argc, char *argv[]) {
    FILE *fd; // File descriptor for the sysfs file.
    if (argc == 1) {    // If no arguments are given, we will read the statistics from the sysfs file.
    // The format of the statistics is: "accepted_packets_cnt,droped_packets_cnt\n" so we will read 2 unsigned ints from the file.
        fd = fopen(PATH, "rb"); // Open the sysfs file for reading.
        if(fd == NULL) {
            printf("Error: Can't open sysfs_device file\n");
            return EXIT_FAILURE; // If the file couldn't be opened, return failure.
        }
        unsigned int accepted_packets_cnt, droped_packets_cnt; // Variables to hold the statistics.
        char statistics[UINT_SIZE * 2]; // Buffer to read the statistics from the sysfs file. (2 unsigned ints)
        
        if (fread(statistics, UINT_SIZE * 2, 1, fd) != 1){
            printf("Error: Can't read from sysfs_device file\n");
            return EXIT_FAILURE; // If the statistics couldn't be read, return failure.
        }; // Read the statistics from the sysfs file to the buffer.
        memcpy((char *)&accepted_packets_cnt, statistics, UINT_SIZE); // Copy the first unsigned int from the buffer to the accept_cnt variable.
        memcpy((char *)&droped_packets_cnt, statistics + UINT_SIZE, UINT_SIZE); // Copy the second unsigned int from the buffer to the drop_cnt variable.

        printf("Firewall Packets Summary:\n"
               "Number of accepted packets: %u\n"
               "Number of dropped packets: %u\n"
               "Total number of packets: %u\n", accepted_packets_cnt, droped_packets_cnt, accepted_packets_cnt + droped_packets_cnt); // Print the statistics.

        fclose(fd); // Close the sysfs file and return success.
        return EXIT_SUCCESS;
        
    }
    if (argc == 2) { // If one argument is given, we will reset the statistics in the sysfs file.
        if (argv[1][0] != 'r') { // If the argument is not 'r', return failure.
            printf("Error: Invalid argument\n");
            return EXIT_FAILURE;
        }
        fd = fopen(PATH, "w"); // Open the sysfs file for writing.
        if(fd == NULL) {
            printf("Error: Can't open sysfs_device file\n");
            return EXIT_FAILURE; // If the file couldn't be opened, return failure.
        }

        // The format of writing to the sysfs file is: "r".
        // We will write 'r' to the sysfs file to reset the statistics.
        char send_reset[] = "r";
        if (fwrite(send_reset, 1, 1, fd)) { // Write '*' to the sysfs file.
            printf("Error: Can't write into sysfs_device file\n");
            return EXIT_FAILURE; // If the '*' couldn't be written, return failure.
        }
        fclose(fd); // Close the sysfs file and return success.
        return EXIT_SUCCESS;
        
    }
    else {
        printf("Error: Invalid number of arguments");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


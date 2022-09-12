#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#define PATHNAME_SIZE 256
#define MAX_FOUND 320000
#define PATHDEPTH 20
//stray hatasini cözmek icin böyle yapmak zorunda kaldım
#define OR ||

struct TargetFileData{
	int flags[6];
	char* path;
	char* filename;
	off_t fileSize;
	char fileType;
	char* permissions;
	nlink_t numOfLinks;
}tfd;

volatile sig_atomic_t keepRunning = 1;

void intHandler(int x) {
    keepRunning = 0;
}


void errExit(const char* errName)
{
	perror(errName);
	exit(EXIT_FAILURE);
}

void print_usage()
{
	char* str = "The search criteria can be any combination of the following" 
				    "(at least one of them must be employed):\n"
				    "• -f : filename (case insensitive), supporting the following regular expression: +\n"
					"• -b : file size (in bytes)\n"
					"• -t : file type (d: directory, s: socket, b: block device, " 
					"c: character device f: regular file, p: pipe, l: symbolic link)\n"
					"• -p : permissions, as 9 characters (e.g. ‘rwxr-xr--’)\n"
					"• -l : number of links\n"
					"• -w: the path in which to search recursively\n"
					"*** -w option is mandantory\n";
	printf("Usage Error:\n%s\n", str);
	exit(EXIT_FAILURE);
}

void getArguments(int argc, char** argv)
{
	char* optstring = "w:f:b:t:p:l:";
	int optionChar;

	if(argc == 3)
	{
		print_usage();
	}

	while((optionChar = getopt(argc, argv, optstring)) != -1)
	{
		switch(optionChar)
		{
			case 'w':
				tfd.path = optarg;
				tfd.flags[0] = 1;
				break;
			case 'f':
				tfd.filename = optarg;
				tfd.flags[1] = 1;
				break;
			case 'b':		
				tfd.fileSize = atoi(optarg);
				tfd.flags[2] = 1;
				break;
			case 't':		
				tfd.fileType = *optarg;
				tfd.flags[3] = 1;
				break;
			case 'p':		
				tfd.permissions = optarg;
				tfd.flags[4] = 1;
				break;
			case 'l':		
				tfd.numOfLinks = atoi(optarg);
				tfd.flags[5] = 1;
				break;	
			default:
				print_usage();
		
		}
	}
	if(tfd.flags[0] != 1)
	{
		printf("error: w option is mandantory\n"
		       "-w: the path in which to search recursively\n");
		exit(EXIT_FAILURE);
	}
}

char inverseLetter(char ch)
{
	if(ch >= 'a' && ch <='z')	
		ch -= 32;
	else if(ch >='A' && ch <= 'Z')
		ch += 32;
	return ch; 
}

//case insensitive and supports '+' regexp
int filenamesWithRegexpMatch(const char* sourceName, const char* targetName)
{
	int i = 0;
	int j = 0;
	int sourceLen = strlen(sourceName);
	int targetLen = strlen(targetName);

	while(i < sourceLen && j < targetLen)
	{
		if(sourceName[i] != '+') 
		{
			if( (sourceName[i] != targetName[j]) &&  
			    (inverseLetter(sourceName[i]) != targetName[j]) )
			{
				return 0;
			}
			++i; ++j;
		}
		else
		{
			char preceding = sourceName[i-1];
			if( (targetName[j] != preceding) && (inverseLetter(targetName[j]) != preceding) && 
			    (targetName[j] != sourceName[i+1]) && (inverseLetter(targetName[j]) != sourceName[i+1]) ) 
			{
				return 0;
			}
			while( (targetName[j] == preceding) OR (inverseLetter(targetName[j]) == preceding) )
				++j;
			++i;
		}
	}
	if(i == sourceLen - 1 && sourceName[i] == '+')
		return 1;
	if(j == targetLen && i == sourceLen)
		return 1;
	else
		return 0;
}

/*void print_statBuf(const struct stat* statBuf)
{
	printf("File Size: \t\t%d bytes\n",statBuf->st_size);
	printf("Number of Links: \t%d\n",statBuf->st_nlink);
	printf("File inode: \t\t%d\n",statBuf->st_ino);
	printf("file type\n");
	printf( (S_ISDIR(statBuf->st_mode)) ? "d\n" : "-\n");
	printf( (S_ISREG(statBuf->st_mode)) ? "regular\n" : "-\n");
	printf("File Permissions: \t");
	printf( (statBuf->st_mode & S_IRUSR) ? "r" : "-");
	printf( (statBuf->st_mode & S_IWUSR) ? "w" : "-");
	printf( (statBuf->st_mode & S_IXUSR) ? "x" : "-");
	printf( (statBuf->st_mode & S_IRGRP) ? "r" : "-");
	printf( (statBuf->st_mode & S_IWGRP) ? "w" : "-");
	printf( (statBuf->st_mode & S_IXGRP) ? "x" : "-");
	printf( (statBuf->st_mode & S_IROTH) ? "r" : "-");
	printf( (statBuf->st_mode & S_IWOTH) ? "w" : "-");
	printf( (statBuf->st_mode & S_IXOTH) ? "x" : "-");

	printf("\nThe file %s a symbolic link\n\n\n", (S_ISLNK(statBuf->st_mode)) ? "is" : "is not");
}*/

//compares file with user specified file
//if matches return 1 
int compare(const struct stat* statBuf, const char* filename)
{
	int matchFilenames = 1;
	int matchFileSize = 1;
	int matchFileType = 1;
	int matchPermissions = 1;
	int matchNumOfLinks = 1;
	//filename
	if(tfd.flags[1] == 1)
	{
		if(filenamesWithRegexpMatch(tfd.filename, filename) == 0)
			matchFilenames = 0;
	}
	//file size
	if(tfd.flags[2] == 1)
	{
		if(tfd.fileSize != statBuf->st_size)
			matchFileSize = 0;
	}
	//file type
	if(tfd.flags[3] == 1)
	{
		switch (tfd.fileType)
		{
			case 'd':
				//directory değilse
				if(!(S_ISDIR(statBuf->st_mode)))
					matchFileType = 0;
				break;
			case 's':
				//socket değilse
				if(!(S_ISSOCK(statBuf->st_mode)))
					matchFileType = 0;
				break;
			case 'b':
				//block device değilse
				if(!(S_ISBLK(statBuf->st_mode)))
					matchFileType = 0;
				break;
			case 'c':
				//character device değilse
				if(!(S_ISCHR(statBuf->st_mode)))
					matchFileType = 0;
				break;
			case 'f':
				//regular file değilse
				if(!(S_ISREG(statBuf->st_mode)))
					matchFileType = 0;
				break;
			case 'p':
				//pipe değilse
				if(!(S_ISFIFO(statBuf->st_mode)))
					matchFileType = 0;
				break;
			case 'l':
				//slink  değilse
				if(!(S_ISLNK(statBuf->st_mode)))
					matchFileType = 0;
				break;
			default:
				matchFileType = 0;
				break;
		}
	}
	//permissions
	if(tfd.flags[4] == 1)
	{ 
		//HANDLE - ?????????
		if(!((tfd.permissions[0] == ((statBuf->st_mode & S_IRUSR) ? 'r' : '-')) &&
		   (tfd.permissions[1] == ((statBuf->st_mode & S_IWUSR) ? 'w' : '-')) &&
		   (tfd.permissions[2] == ((statBuf->st_mode & S_IXUSR) ? 'x' : '-')) &&
		   (tfd.permissions[3] == ((statBuf->st_mode & S_IRGRP) ? 'r' : '-')) &&
		   (tfd.permissions[4] == ((statBuf->st_mode & S_IWGRP) ? 'w' : '-')) &&
		   (tfd.permissions[5] == ((statBuf->st_mode & S_IXGRP) ? 'x' : '-')) &&
		   (tfd.permissions[6] == ((statBuf->st_mode & S_IROTH) ? 'r' : '-')) &&
		   (tfd.permissions[7] == ((statBuf->st_mode & S_IWOTH) ? 'w' : '-')) &&
		   (tfd.permissions[8] == ((statBuf->st_mode & S_IXOTH) ? 'x' : '-'))))
		{
			matchPermissions = 0;
		}
	}
	//number of hard links
	if(tfd.flags[5] == 1)
	{
		if(tfd.numOfLinks != statBuf->st_nlink)
		{
			matchNumOfLinks = 0;
		}
	}

	return (matchFilenames && matchFileSize && matchFileType && matchPermissions 
		   && matchNumOfLinks);
}

//search all directories under the given pathname
void search(char *basePath, char** found, int* foundCount)
{
    char path[PATHNAME_SIZE];
    
	struct dirent *dp;
    DIR *dir = opendir(basePath);
	
	struct stat statBuf;
	memset(&statBuf,0,sizeof(statBuf));
	if (!dir)
		return;

	while ( ((dp = readdir(dir)) != NULL) && keepRunning)
    {
		if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {
            strcpy(path, basePath);
            strcat(path, "/");
            strcat(path, dp->d_name);
			if(lstat (path, &statBuf) < 0)
				errExit("lstat error: ");
			else
			{	
				if(S_ISLNK(statBuf.st_mode))
				{
					continue;
				}
				if(compare(&statBuf, dp->d_name))
	 			{
					strcpy(found[*foundCount], path);
					++(*foundCount);
	 			}
			}
			search(path, found, foundCount);
        }
    }
    closedir(dir);
}

//kendinden önce bastırılan path ile baştan kaç dosya ismi aynı
int similarity_count(char** path1, int len1, char** path2, int len2)
{
	int i;
	int len = (len1 < len2) ? len1 : len2;
	int count = 0;
	for(i = 0; i < len; ++i)
	{
		if(strcmp(path1[i], path2[i]) == 0)
		{
			++count;
		}
		else
			break;
	}
	return count;
}

//kendinden önce bastırılan pathlerden hangisine daha çok benziyor
//indexini döndürür
int most_similar(char*** paths, char** targetPath, int foundCount, int selfIndex, int* lengths, int limit)
{
	int i;
	int mostSimilarIndex = 0;
	int max = 0;
	int ret;
	for(i = 0; i < limit; ++i)
	{
		if(i != selfIndex)
		{
			ret = similarity_count(paths[i], lengths[i], targetPath, lengths[selfIndex]);
			if(ret > max)
			{
				max = ret;
				mostSimilarIndex = i;
			} 
		}		
	}
	return mostSimilarIndex;
}


void print_tree(char** found, int foundCount)
{
	int i, k;
	int j = 0;
	//char* toPrint[foundCount][30];
	char*** toPrint = (char***) malloc(sizeof(char*) * foundCount * PATHDEPTH);
	for(i = 0; i < foundCount; ++i)
		toPrint[i] = (char**) malloc(sizeof(char**) * PATHDEPTH);
	int lengths[foundCount];
	for(i = 0; i < foundCount; ++i)
	{
		j = 0;
		if(found[i][0] == '/')
		{
			toPrint[i][j] = "/";
			++j;
		}
		toPrint[i][j] = strtok(found[i], "/");
		
		while (toPrint[i][j] != NULL) {
			++j;
			toPrint[i][j] = strtok(NULL, "/");
    	}
		lengths[i] = j;
	}
	//print first one
	for(i = 0; i < lengths[0]; ++i)
	{
		if(i != 0)
			printf("|");
		for(j = 0; j < i; ++j)
			printf("--");
		if(i == (lengths[0] -1))
			printf ("\033[32;1m%s \033[0m\n", toPrint[0][j]);
		else
			printf("%s\n", toPrint[0][i]);
	}
	int limit = 1;
	//print rest
	//kendisinden önce yazılalanlardan hangisine en çok benziyor
	for(i = 1; i < foundCount && keepRunning; ++i)
	{
		//i en çok hangisine benziyor
		int mostSimInd = most_similar(toPrint, toPrint[i], foundCount, i, lengths, limit);
		//ne kadar benziyor
		int simScore = similarity_count(toPrint[mostSimInd], lengths[mostSimInd], toPrint[i], lengths[i]);
		for(j = simScore; j < lengths[i]; ++j)
		{
			printf("|");
			for(k = 0; k < j; ++k)
				printf("--");
			if(j == (lengths[i] - 1))
				printf ("\033[32;1m%s \033[0m\n", toPrint[i][j]);
			else
				printf("%s\n", toPrint[i][j]);
		}
		++limit;
	}
	for(i = 0; i < foundCount; ++i)
		free(toPrint[i]);
	free(toPrint);
}

int main(int argc, char** argv)
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
    act.sa_handler = intHandler;
    sigaction(SIGINT, &act, NULL);

	int i;
	//number of founded files
	int foundCount = 0;
	
	memset(&tfd, 0, sizeof(struct TargetFileData));
	
	getArguments(argc, argv);
	//allocate memory for found
	char **found = (char**)malloc(MAX_FOUND * sizeof(char *));
	for(i = 0; i < MAX_FOUND; ++i)
	{
		found[i] = (char*)malloc(PATHNAME_SIZE * sizeof(char));
	}
	
	//search given path
	//fill found with the founded file's path
	//foundCount filled with the number of found
	if(keepRunning)
		search(tfd.path, found, &foundCount);
	if(foundCount == 0)
	{
		printf("No file found\n");
		for(i = 0; i < MAX_FOUND; ++i) {
			free(found[i]);   
		}
		free(found);
		return 0;
	}

	if(keepRunning)
		printf("%d files are found\n\n", foundCount);
	if(keepRunning)
		print_tree(found, foundCount);
	
	if(!keepRunning)
		printf("SIGINT arrived exiting program\n");
	//free
	for(i = 0; i < MAX_FOUND; ++i) {
		free(found[i]);   
	}
	free(found);
	return 0;
}
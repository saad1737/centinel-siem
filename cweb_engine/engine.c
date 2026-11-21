#include <cweb.h>

HandlerState hello_world(CwebContext* ctx) {
    send_text(ctx, 200, "Hello World");
    return DB_DONE;
}

int main() {
    insert_route(GET, "/", hello_world);

    return cweb_run_server(1234, NULL, 0);
}
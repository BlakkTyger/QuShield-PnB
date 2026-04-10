/**
 * Login layout — strips the Sidebar and Header so the login page
 * renders as a full-screen experience.
 */
export default function LoginLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return <>{children}</>;
}

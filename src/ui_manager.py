"""
Enhanced UI Manager với Rich Console
Professional grade UI cho TLS/SSL demo
"""
import sys
import time
from datetime import datetime
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback cho khi không có Rich
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

class UIManager:
    """Enhanced UI Manager cho professional display"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else Console()
        self.theme_color = "cyan"
        
    def show_banner(self):
        """Hiển thị professional banner"""
        if RICH_AVAILABLE:
            banner_text = """
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED TLS/SSL SECURITY SUITE                    ║
║          Professional Grade Cryptographic Analysis           ║
║          🔐 PTIT - Network Security Protocols 🔐            ║
╚══════════════════════════════════════════════════════════════╝
            """
            
            panel = Panel(
                banner_text,
                style="bold cyan",
                border_style="bright_blue",
                expand=False
            )
            
            self.console.print()
            self.console.print(Align.center(panel))
            self.console.print()
            
            # System info
            info_table = Table(show_header=False, box=None, padding=(0, 2))
            info_table.add_column(style="cyan")
            info_table.add_column(style="white")
            
            info_table.add_row("🗓️  Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            info_table.add_row("🐍 Python:", f"{sys.version.split()[0]}")
            info_table.add_row("📚 Features:", "Manual TLS Handshake, Security Analysis, Crypto Demos")
            info_table.add_row("🎯 Purpose:", "Educational & Professional Security Analysis")
            
            self.console.print(Align.center(info_table))
            self.console.print()
        else:
            # Fallback
            print("""
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED TLS/SSL SECURITY SUITE                    ║
║          Professional Grade Cryptographic Analysis           ║
║          🔐 PTIT - Network Security Protocols 🔐            ║
╚══════════════════════════════════════════════════════════════╝
            """)
    
    def show_main_menu(self):
        """Hiển thị main menu với rich formatting"""
        if RICH_AVAILABLE:
            menu_table = Table(
                title="🔐 TLS/SSL Security Suite - Main Menu",
                show_header=True,
                header_style="bold magenta",
                border_style="blue",
                title_style="bold cyan"
            )
            
            menu_table.add_column("Option", style="cyan", width=8)
            menu_table.add_column("Category", style="green", width=20)
            menu_table.add_column("Description", style="white")
            menu_table.add_column("Difficulty", style="yellow", width=12)
            
            # Basic Operations
            menu_table.add_row("1", "📋 Certificate", "Generate TLS Certificates", "Basic")
            menu_table.add_row("2", "🚀 Server", "Start TLS Server", "Basic")
            menu_table.add_row("3", "📡 Client", "Run TLS Client", "Basic")
            menu_table.add_row("4", "🔐 Crypto", "Basic Encryption Demo", "Basic")
            
            menu_table.add_section()
            menu_table.add_row("0", "👋 Exit", "Exit Application", "-")
            
            self.console.print(menu_table)
            
        else:
            # Fallback menu
            print("\n" + "="*80)
            print("🔐 BASIC TLS/SSL DEMO OPTIONS:")
            print("="*80)
            print("📋 CORE OPERATIONS:")
            print("  1. Generate Certificates (CA & Server)")
            print("  2. Start TLS Server")
            print("  3. Run TLS Client (connect to server)")
            print("  4. Demo Encryption Algorithms (AES-GCM, RSA)")
            print()
            print("  0. Exit")
            print("="*80)
    
    def show_section_header(self, title, description=None):
        """Hiển thị section header"""
        if RICH_AVAILABLE:
            if description:
                content = f"[bold]{title}[/bold]\n{description}"
            else:
                content = f"[bold]{title}[/bold]"
                
            panel = Panel(
                content,
                style="cyan",
                border_style="blue",
                expand=False
            )
            self.console.print(panel)
        else:
            print(f"\n{'='*80}")
            print(f"🔐 {title}")
            if description:
                print(f"{description}")
            print('='*80)
    
    def show_progress(self, tasks, description="Processing"):
        """Hiển thị progress bar"""
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                for task in tasks:
                    task_id = progress.add_task(f"{description}: {task}", total=None)
                    time.sleep(1)  # Simulate work
                    progress.update(task_id, completed=True)
        else:
            for task in tasks:
                print(f"Processing: {task}")
                time.sleep(1)
    
    def show_status(self, message, status="info"):
        """Hiển thị status message"""
        if RICH_AVAILABLE:
            if status == "success":
                self.console.print(f"✅ {message}", style="green")
            elif status == "error":
                self.console.print(f"❌ {message}", style="red")
            elif status == "warning":
                self.console.print(f"⚠️  {message}", style="yellow")
            else:
                self.console.print(f"ℹ️  {message}", style="cyan")
        else:
            status_icons = {
                "success": "✅",
                "error": "❌", 
                "warning": "⚠️ ",
                "info": "ℹ️ "
            }
            print(f"{status_icons.get(status, 'ℹ️ ')} {message}")
    
    def show_table(self, title, headers, rows, styles=None):
        """Hiển thị table với rich formatting"""
        if RICH_AVAILABLE:
            table = Table(title=title, show_header=True, header_style="bold magenta")
            
            # Add columns
            for i, header in enumerate(headers):
                style = styles[i] if styles and i < len(styles) else "white"
                table.add_column(header, style=style)
            
            # Add rows
            for row in rows:
                table.add_row(*[str(cell) for cell in row])
            
            self.console.print(table)
        else:
            print(f"\n{title}")
            print("-" * len(title))
            
            # Print headers
            header_line = " | ".join(headers)
            print(header_line)
            print("-" * len(header_line))
            
            # Print rows
            for row in rows:
                row_line = " | ".join(str(cell) for cell in row)
                print(row_line)
    
    def show_tree_structure(self, title, structure):
        """Hiển thị tree structure"""
        if RICH_AVAILABLE:
            tree = Tree(f"[bold cyan]{title}[/bold cyan]")
            
            def add_items(parent, items):
                if isinstance(items, dict):
                    for key, value in items.items():
                        if isinstance(value, (dict, list)):
                            branch = parent.add(f"[green]{key}[/green]")
                            add_items(branch, value)
                        else:
                            parent.add(f"[green]{key}[/green]: [white]{value}[/white]")
                elif isinstance(items, list):
                    for item in items:
                        if isinstance(item, (dict, list)):
                            add_items(parent, item)
                        else:
                            parent.add(f"[white]{item}[/white]")
            
            add_items(tree, structure)
            self.console.print(tree)
        else:
            print(f"\n{title}")
            print("-" * len(title))
            
            def print_items(items, indent=0):
                prefix = "  " * indent
                if isinstance(items, dict):
                    for key, value in items.items():
                        if isinstance(value, (dict, list)):
                            print(f"{prefix}├─ {key}")
                            print_items(value, indent + 1)
                        else:
                            print(f"{prefix}├─ {key}: {value}")
                elif isinstance(items, list):
                    for item in items:
                        if isinstance(item, (dict, list)):
                            print_items(item, indent)
                        else:
                            print(f"{prefix}├─ {item}")
            
            print_items(structure)
    
    def get_user_input(self, prompt="Select option: "):
        """Get user input với enhanced prompt"""
        if RICH_AVAILABLE:
            return self.console.input(f"[bold cyan]{prompt}[/bold cyan]")
        else:
            return input(prompt)
    
    def show_error(self, error_message, details=None):
        """Hiển thị error message"""
        if RICH_AVAILABLE:
            content = f"[bold red]Error:[/bold red] {error_message}"
            if details:
                content += f"\n[dim]{details}[/dim]"
            
            panel = Panel(
                content,
                title="⚠️  Error",
                style="red",
                border_style="red"
            )
            self.console.print(panel)
        else:
            print(f"\n❌ Error: {error_message}")
            if details:
                print(f"Details: {details}")
    
    def show_success(self, message, details=None):
        """Hiển thị success message"""
        if RICH_AVAILABLE:
            content = f"[bold green]Success:[/bold green] {message}"
            if details:
                content += f"\n[dim]{details}[/dim]"
            
            panel = Panel(
                content,
                title="✅ Success", 
                style="green",
                border_style="green"
            )
            self.console.print(panel)
        else:
            print(f"\n✅ Success: {message}")
            if details:
                print(f"Details: {details}")
    
    def show_warning(self, message, details=None):
        """Hiển thị warning message"""  
        if RICH_AVAILABLE:
            content = f"[bold yellow]Warning:[/bold yellow] {message}"
            if details:
                content += f"\n[dim]{details}[/dim]"
            
            panel = Panel(
                content,
                title="⚠️  Warning",
                style="yellow", 
                border_style="yellow"
            )
            self.console.print(panel)
        else:
            print(f"\n⚠️  Warning: {message}")
            if details:
                print(f"Details: {details}")
    
    def pause(self, message="Press Enter to continue..."):
        """Pause execution"""
        if RICH_AVAILABLE:
            self.console.input(f"[dim]{message}[/dim]")
        else:
            input(message)


# Global UI instance
ui = UIManager()